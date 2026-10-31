//! The Approval object (plan Appendix A `Approval`, FA-INV-10
//! `approval-binds-proposal`, §14.5 non-repudiation).
//!
//! An approval binds the *proposal* digest it approves — never a committed
//! envelope — together with the approver, the profile and capability
//! commitment it acted under, the op it exercised, the book, and the
//! security policy epoch current when it was recorded. Its recorded
//! sequence is its vertex's `created_at`.
//!
//! Subset of the Appendix A row, stated: `effects_digest` and
//! `target_coordinate` are not carried yet. Rule-generated effects do not
//! exist in this slice (an entry's effects are its proposal's legs, which
//! the proposal digest already binds), and trunk is the only coordinate.
//! They arrive additively with Canon and branches.

use fa_model::{DecodeError, EncodeError, Id128, Reader, Writer, domain_digest};
use fgdb_types::VId;

use crate::capability::{Capability, CapabilityError, Profile};
use crate::denial::Denial;
use crate::op::Op;
use crate::principal_key::ApprovalSignature;

pub const APPROVAL_DOMAIN: &[u8] = b"fa:approval:v1";
const APPROVAL_VERSION: u16 = 1;
const SIGNED_RECORD_VERSION: u16 = 2;
/// A version-1 body is exactly 110 bytes; a record may not smuggle more.
const MAX_BODY_BYTES: usize = 2 + 16 + 16 + 1 + 32 + 32 + 8 + 1 + 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub book_id: Id128,
    pub principal: VId,
    pub profile: Profile,
    pub capability_commitment: [u8; 32],
    pub approved_proposal_digest: [u8; 32],
    pub security_policy_epoch: u64,
    /// The op the approver's capability held and exercised (`approve`).
    pub op: Op,
    /// The approver's declared role (0 = unspecified; registered roles land
    /// with the profile registry).
    pub role: u16,
}

impl Approval {
    /// Build the approval `cap` records over `approved_proposal_digest`:
    /// the capability must hold `op`. Expiry is checked by the caller at its
    /// admission point ([`crate::current`]).
    pub fn by(
        cap: &Capability,
        op: Op,
        book_id: Id128,
        approved_proposal_digest: [u8; 32],
        security_policy_epoch: u64,
        role: u16,
    ) -> Result<Result<Self, Denial>, CapabilityError> {
        if let Err(d) = crate::require(cap, op, "recording an approval") {
            return Ok(Err(d));
        }
        Ok(Ok(Self {
            book_id,
            principal: cap.holder(),
            profile: cap.sod_profile(),
            capability_commitment: cap.commitment()?,
            approved_proposal_digest,
            security_policy_epoch,
            op,
            role,
        }))
    }

    /// `u16 version ‖ id128 book ‖ u128 principal ‖ u8 profile ‖ [32]
    /// capability_commitment ‖ [32] approved_proposal_digest ‖ u64 epoch ‖
    /// u8 op ‖ u16 role`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::with_capacity(2 + 16 + 16 + 1 + 32 + 32 + 8 + 1 + 2);
        w.u16(APPROVAL_VERSION)
            .fixed(&self.book_id.0)
            .u128(self.principal.0)
            .u8(self.profile.tag())
            .fixed(&self.capability_commitment)
            .fixed(&self.approved_proposal_digest)
            .u64(self.security_policy_epoch)
            .u8(self.op.tag())
            .u16(self.role);
        w.finish()
    }

    /// `BLAKE3("fa:approval:v1" ‖ len ‖ canonical_bytes)`.
    pub fn digest(&self) -> Result<[u8; 32], EncodeError> {
        Ok(domain_digest(APPROVAL_DOMAIN, &[&self.canonical_bytes()?]))
    }

    /// The bytes an Approval vertex stores: the version-1 body alone, or,
    /// for a principal's signed approval, the version-2 record `u16 2 ‖
    /// bytes body ‖ u16 scheme ‖ u32 generation ‖ [32] key_id ‖ [64]
    /// signature`. The digest, the approval's identity and what the
    /// signature signs are all the body's, so the signature stays outside
    /// the signed digest (plan Appendix A, bead fa-kae).
    pub fn record_bytes(
        &self,
        signature: Option<&ApprovalSignature>,
    ) -> Result<Vec<u8>, EncodeError> {
        let body = self.canonical_bytes()?;
        let Some(signature) = signature else {
            return Ok(body);
        };
        let mut w = Writer::with_capacity(2 + 4 + body.len() + 2 + 4 + 32 + 64);
        w.u16(SIGNED_RECORD_VERSION)
            .bytes(&body)
            .u16(signature.scheme)
            .u32(signature.generation)
            .fixed(&signature.key_id)
            .fixed(&signature.bytes);
        w.finish()
    }

    /// A stored record: the approval and, for version 2, its signature.
    pub fn decode_record(bytes: &[u8]) -> Result<(Self, Option<ApprovalSignature>), DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("approval.version")? != SIGNED_RECORD_VERSION {
            return Ok((Self::decode_body(bytes)?, None));
        }
        let approval = Self::decode_body(r.bytes(MAX_BODY_BYTES, "approval.body")?)?;
        let signature = ApprovalSignature {
            scheme: r.u16("approval.signature.scheme")?,
            generation: r.u32("approval.signature.generation")?,
            key_id: r.fixed("approval.signature.key_id")?,
            bytes: r.fixed("approval.signature.bytes")?,
        };
        r.finish()?;
        Ok((approval, Some(signature)))
    }

    /// The approval a stored record carries, signed or not.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode_record(bytes).map(|(approval, _)| approval)
    }

    fn decode_body(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("approval.version")? != APPROVAL_VERSION {
            return Err(r.invalid("approval.version"));
        }
        let book_id = Id128(r.fixed("approval.book_id")?);
        let principal = VId(r.u128("approval.principal")?);
        let p = r.u8("approval.profile")?;
        let profile = Profile::from_tag(p).ok_or_else(|| r.bad_tag("approval.profile", p))?;
        let capability_commitment = r.fixed("approval.capability_commitment")?;
        let approved_proposal_digest = r.fixed("approval.approved_proposal_digest")?;
        let security_policy_epoch = r.u64("approval.security_policy_epoch")?;
        let t = r.u8("approval.op")?;
        let op = Op::from_tag(t).ok_or_else(|| r.bad_tag("approval.op", t))?;
        let role = r.u16("approval.role")?;
        r.finish()?;
        if profile.forbidden_ops().contains(&op) {
            return Err(DecodeError {
                offset: 0,
                what: "approval.op",
                reason: fa_model::canon::Reason::Invalid,
            });
        }
        Ok(Self {
            book_id,
            principal,
            profile,
            capability_commitment,
            approved_proposal_digest,
            security_policy_epoch,
            op,
            role,
        })
    }

    /// The witnessed approval, cited as transcript item `index`, binds this
    /// proposal in this book under the current epoch. `cited_digest` is the
    /// `ApprovalRef.approved_digest` the transcript carries.
    pub fn check_binding(
        &self,
        index: usize,
        cited_digest: &[u8; 32],
        proposal_digest: &[u8; 32],
        book_id: Id128,
        current_epoch: u64,
    ) -> Result<(), Denial> {
        if cited_digest != proposal_digest
            || &self.approved_proposal_digest != proposal_digest
            || self.book_id != book_id
        {
            return Err(Denial::ApprovalBinding { index });
        }
        if self.security_policy_epoch != current_epoch {
            return Err(Denial::StaleApproval {
                index,
                recorded_epoch: self.security_policy_epoch,
                current_epoch,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Approval {
        let cap = Capability::embedded(VId(9), &["approve"]).unwrap();
        Approval::by(&cap, Op::Approve, Id128([4; 16]), [7; 32], 3, 0)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn approval_round_trips_and_its_digest_binds_every_field() {
        let a = sample();
        let bytes = a.canonical_bytes().unwrap();
        assert_eq!(Approval::decode(&bytes).unwrap(), a);
        let d = a.digest().unwrap();
        let mut b = a.clone();
        b.security_policy_epoch = 4;
        assert_ne!(b.digest().unwrap(), d);
        let mut c = a.clone();
        c.approved_proposal_digest = [8; 32];
        assert_ne!(c.digest().unwrap(), d);
        let mut long = bytes;
        long.push(1);
        assert!(Approval::decode(&long).is_err());
    }

    /// A signed record carries the unchanged v1 body: the same approval,
    /// the same digest, its signature beside it; a malformed record is
    /// refused.
    #[test]
    fn a_signed_record_keeps_the_body_and_its_digest() {
        let a = sample();
        let unsigned = a.record_bytes(None).unwrap();
        assert_eq!(unsigned, a.canonical_bytes().unwrap());
        assert_eq!(
            Approval::decode_record(&unsigned).unwrap(),
            (a.clone(), None)
        );
        let signature = ApprovalSignature {
            scheme: crate::principal_key::SCHEME_ED25519,
            generation: 2,
            key_id: [5; 32],
            bytes: [6; 64],
        };
        let signed = a.record_bytes(Some(&signature)).unwrap();
        assert_eq!(
            Approval::decode_record(&signed).unwrap(),
            (a.clone(), Some(signature))
        );
        assert_eq!(
            Approval::decode(&signed).unwrap().digest().unwrap(),
            a.digest().unwrap()
        );
        let mut long = signed.clone();
        long.push(0);
        assert!(Approval::decode_record(&long).is_err());
        let mut short = signed;
        short.pop();
        assert!(Approval::decode_record(&short).is_err());
        // A version-2 record whose body is itself a record is refused.
        let nested = Approval::decode_record(&{
            let mut w = Writer::new();
            w.u16(SIGNED_RECORD_VERSION)
                .bytes(&[0; MAX_BODY_BYTES + 1])
                .u16(1)
                .u32(0)
                .fixed(&[0; 32])
                .fixed(&[0; 64]);
            w.finish().unwrap()
        });
        assert!(nested.is_err());
    }

    #[test]
    fn recording_requires_the_op_and_binding_is_exact() {
        let reader = Capability::embedded(VId(9), &["read"]).unwrap();
        let d = Approval::by(&reader, Op::Approve, Id128([4; 16]), [7; 32], 0, 0)
            .unwrap()
            .unwrap_err();
        assert_eq!(d.code(), "FA-REF-011");
        let a = sample();
        assert_eq!(
            a.check_binding(0, &[7; 32], &[7; 32], Id128([4; 16]), 3),
            Ok(())
        );
        assert_eq!(
            a.check_binding(1, &[7; 32], &[6; 32], Id128([4; 16]), 3),
            Err(Denial::ApprovalBinding { index: 1 })
        );
        assert_eq!(
            a.check_binding(0, &[6; 32], &[7; 32], Id128([4; 16]), 3),
            Err(Denial::ApprovalBinding { index: 0 })
        );
        assert_eq!(
            a.check_binding(0, &[7; 32], &[7; 32], Id128([5; 16]), 3),
            Err(Denial::ApprovalBinding { index: 0 })
        );
        let stale = a
            .check_binding(0, &[7; 32], &[7; 32], Id128([4; 16]), 4)
            .unwrap_err();
        assert_eq!((stale.code(), stale.exit()), ("FA-REF-022", 6));
    }
}
