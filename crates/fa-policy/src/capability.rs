//! The typed capability (plan §14.2, §14.4, Appendix A `Capability`).
//!
//! A capability is a conjunction of caveats held by one principal: the ops
//! it may exercise, per-unit amount ceilings, a declared expiry, and the
//! profile template it was issued under. It is a value with canonical bytes
//! (`fa:capability:v1`) and a commitment digest an approval or a certificate
//! binds; every constructor and the decoder enforce the profile law, so an
//! Agent-profile capability that holds `approve` cannot exist.
//!
//! **Expiry is a declared `CommitSeq` bound.** `expires_at = Some(n)`
//! admits at an admission point `at` iff `at < n`. The admission point is
//! an explicit input (plan §14.2 "expiry admission"): the kernel passes the
//! book head it observed just before opening the posting transaction on
//! the single-writer handle. Wall-clock expiry arrives with TimeEvidence;
//! this crate never reads a clock.
//!
//! **Trust boundary.** This crate decides whether a capability authorizes
//! an act; it does not decide whether the caller holds the capability. In
//! the embedded posture the calling process is the principal's own agent and
//! [`Capability::embedded`] self-issues; the daemon/MCP posture binds the
//! capability from an authenticated session before calling the kernel.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fa_model::{DecodeError, EncodeError, Reader, Writer, domain_digest};
use fa_money::UnitId;
use fgdb_types::{CommitSeq, VId};

use crate::op::Op;

pub const CAPABILITY_DOMAIN: &[u8] = b"fa:capability:v1";
const CAPABILITY_VERSION: u16 = 1;
/// Ceilings per capability, bounded so a decoder never allocates on a claim.
pub const MAX_CEILINGS: usize = 256;

/// The base profile templates (plan §14.4). Preparer/Approver/Controller and
/// the external profiles are op sets over `Human`; `Agent` and `System` carry
/// laws of their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Profile {
    Human,
    /// Branch-confined: never writes trunk, never approves, closes, reopens,
    /// restates, issues capabilities, changes rules or schema, or erases.
    Agent,
    /// The book's intrinsic actors (the expiry sweep, the register
    /// maintainer). A system never approves and never issues capabilities.
    System,
}

impl Profile {
    pub const ALL: [Self; 3] = [Self::Human, Self::Agent, Self::System];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Human => "Human",
            Self::Agent => "Agent",
            Self::System => "System",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Human => 0,
            Self::Agent => 1,
            Self::System => 2,
        }
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.tag() == tag)
    }

    /// Ops this profile can never hold, with the plan clause that forbids them.
    #[must_use]
    pub fn forbidden_ops(self) -> &'static [Op] {
        match self {
            Self::Human => &[],
            // §14.4: no approve/close/restate (reopen is close's inverse);
            // no self-escalation (issue_capability); schema and rule changes
            // are draft effects a human promotes; erasure, privilege and
            // receivership are human authority.
            Self::Agent => &[
                Op::Approve,
                Op::Close,
                Op::Reopen,
                Op::Restate,
                Op::SchemaChange,
                Op::RuleChange,
                Op::IssueCapability,
                Op::Erase,
                Op::Privileged,
                Op::Receivership,
            ],
            // §14.5: an approval is a principal's attributable judgment.
            Self::System => &[Op::Approve, Op::IssueCapability],
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a capability could not be built or decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityError {
    UnknownOp {
        name: String,
        nearest: Option<Op>,
    },
    ForbiddenOp {
        profile: Profile,
        op: Op,
    },
    /// A ceiling must be a positive mantissa.
    BadCeiling {
        unit: UnitId,
        max_mantissa: i128,
    },
    TooManyCeilings,
    Decode(DecodeError),
    Encode(EncodeError),
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOp { name, nearest } => {
                write!(f, "`{name}` is not a capability op")?;
                match nearest {
                    Some(op) => write!(f, "; did you mean `{op}`?"),
                    None => write!(f, "; `fa capabilities --json` lists the vocabulary"),
                }
            }
            Self::ForbiddenOp { profile, op } => {
                write!(
                    f,
                    "a {profile}-profile capability can never hold `{op}` (plan §14.4)"
                )
            }
            Self::BadCeiling { unit, max_mantissa } => write!(
                f,
                "ceiling {max_mantissa} for unit {} is not a positive mantissa",
                unit.0
            ),
            Self::TooManyCeilings => write!(f, "more than {MAX_CEILINGS} ceilings"),
            Self::Decode(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for CapabilityError {}

/// A capability: conjunctive caveats held by one principal (plan §14.2).
/// Fields are private so the profile law holds for every value that exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    holder: VId,
    profile: Profile,
    ops: BTreeSet<Op>,
    /// `amount ≤ A` per leg, per unit: the maximum mantissa at the unit's
    /// scale. A capability that carries any ceiling admits only the units it
    /// bounds (fail closed: a bounded token is bounded everywhere).
    ceilings: BTreeMap<UnitId, i128>,
    expires_at: Option<CommitSeq>,
    issuer: VId,
}

impl Capability {
    /// A capability under `profile`; refuses ops the profile can never hold.
    pub fn new(
        holder: VId,
        profile: Profile,
        ops: &[Op],
        issuer: VId,
    ) -> Result<Self, CapabilityError> {
        let ops: BTreeSet<Op> = ops.iter().copied().collect();
        if let Some(op) = profile.forbidden_ops().iter().find(|op| ops.contains(op)) {
            return Err(CapabilityError::ForbiddenOp { profile, op: *op });
        }
        Ok(Self {
            holder,
            profile,
            ops,
            ceilings: BTreeMap::new(),
            expires_at: None,
            issuer,
        })
    }

    /// The embedded posture's binding (`fa --as <principal> --grant <op>`):
    /// a Human-profile capability the calling process self-issues for the
    /// principal it acts as, with no ceilings and no expiry. Names are the
    /// registered op names; an unknown name is refused with the nearest one.
    pub fn embedded(holder: VId, op_names: &[&str]) -> Result<Self, CapabilityError> {
        let mut ops = Vec::with_capacity(op_names.len());
        for name in op_names {
            ops.push(
                Op::from_name(name).ok_or_else(|| CapabilityError::UnknownOp {
                    name: (*name).to_string(),
                    nearest: Op::nearest(name),
                })?,
            );
        }
        Self::new(holder, Profile::Human, &ops, holder)
    }

    /// Add (or tighten) the per-leg ceiling for `unit`.
    pub fn with_ceiling(
        mut self,
        unit: UnitId,
        max_mantissa: i128,
    ) -> Result<Self, CapabilityError> {
        if max_mantissa <= 0 {
            return Err(CapabilityError::BadCeiling { unit, max_mantissa });
        }
        let slot = self.ceilings.entry(unit).or_insert(max_mantissa);
        *slot = (*slot).min(max_mantissa);
        if self.ceilings.len() > MAX_CEILINGS {
            return Err(CapabilityError::TooManyCeilings);
        }
        Ok(self)
    }

    /// Declare the expiry bound: admitted only at admission points `< at`.
    /// A second call can only tighten it.
    #[must_use]
    pub fn expiring_at(mut self, at: CommitSeq) -> Self {
        self.expires_at = Some(self.expires_at.map_or(at, |e| e.min(at)));
        self
    }

    #[must_use]
    pub fn holder(&self) -> VId {
        self.holder
    }

    #[must_use]
    pub fn profile(&self) -> Profile {
        self.profile
    }

    #[must_use]
    pub fn ops(&self) -> &BTreeSet<Op> {
        &self.ops
    }

    #[must_use]
    pub fn holds(&self, op: Op) -> bool {
        self.ops.contains(&op)
    }

    #[must_use]
    pub fn ceilings(&self) -> &BTreeMap<UnitId, i128> {
        &self.ceilings
    }

    #[must_use]
    pub fn expires_at(&self) -> Option<CommitSeq> {
        self.expires_at
    }

    #[must_use]
    pub fn issuer(&self) -> VId {
        self.issuer
    }

    /// `u16 version ‖ u128 holder ‖ u8 profile ‖ list(u8 op tag, ascending)
    /// ‖ list(u32 unit ‖ i128 max, ascending by unit) ‖ opt(u64 expires_at)
    /// ‖ u128 issuer`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CapabilityError> {
        let ops: Vec<u8> = self.ops.iter().map(|op| op.tag()).collect();
        let ceilings: Vec<(UnitId, i128)> = self.ceilings.iter().map(|(u, m)| (*u, *m)).collect();
        let mut w = Writer::with_capacity(64 + ops.len() + ceilings.len() * 20);
        w.u16(CAPABILITY_VERSION)
            .u128(self.holder.0)
            .u8(self.profile.tag())
            .list(&ops, |w, t| {
                w.u8(*t);
            })
            .list(&ceilings, |w, (u, m)| {
                w.u32(u.0).i128(*m);
            })
            .opt(self.expires_at.as_ref(), |w, s| {
                w.u64(s.0);
            })
            .u128(self.issuer.0);
        w.finish().map_err(CapabilityError::Encode)
    }

    /// The commitment an approval or a certificate binds:
    /// `BLAKE3("fa:capability:v1" ‖ len ‖ canonical_bytes)`.
    pub fn commitment(&self) -> Result<[u8; 32], CapabilityError> {
        Ok(domain_digest(
            CAPABILITY_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }

    /// Decode canonical bytes; refuses unknown tags, unsorted or duplicate
    /// collections, non-positive ceilings, the profile law, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CapabilityError> {
        let mut r = Reader::new(bytes);
        let version = r
            .u16("capability.version")
            .map_err(CapabilityError::Decode)?;
        if version != CAPABILITY_VERSION {
            return Err(CapabilityError::Decode(r.invalid("capability.version")));
        }
        let holder = VId(r
            .u128("capability.holder")
            .map_err(CapabilityError::Decode)?);
        let profile_tag = r
            .u8("capability.profile")
            .map_err(CapabilityError::Decode)?;
        let profile = Profile::from_tag(profile_tag)
            .ok_or_else(|| CapabilityError::Decode(r.bad_tag("capability.profile", profile_tag)))?;
        let tags = r
            .list(Op::ALL.len(), "capability.ops", |r| r.u8("capability.op"))
            .map_err(CapabilityError::Decode)?;
        let mut ops = Vec::with_capacity(tags.len());
        for t in &tags {
            ops.push(
                Op::from_tag(*t)
                    .ok_or_else(|| CapabilityError::Decode(r.bad_tag("capability.op", *t)))?,
            );
        }
        if !ops.windows(2).all(|w| w[0] < w[1]) {
            return Err(CapabilityError::Decode(r.unsorted("capability.ops")));
        }
        let ceilings = r
            .list(MAX_CEILINGS, "capability.ceilings", |r| {
                Ok((UnitId(r.u32("ceiling.unit")?), r.i128("ceiling.max")?))
            })
            .map_err(CapabilityError::Decode)?;
        if !ceilings.windows(2).all(|w| w[0].0 < w[1].0) {
            return Err(CapabilityError::Decode(r.unsorted("capability.ceilings")));
        }
        let expires_at = r
            .opt("capability.expires_at", |r| {
                r.u64("capability.expires_at").map(CommitSeq)
            })
            .map_err(CapabilityError::Decode)?;
        let issuer = VId(r
            .u128("capability.issuer")
            .map_err(CapabilityError::Decode)?);
        r.finish().map_err(CapabilityError::Decode)?;
        let mut cap = Self::new(holder, profile, &ops, issuer)?;
        for (unit, max) in ceilings {
            cap = cap.with_ceiling(unit, max)?;
        }
        cap.expires_at = expires_at;
        Ok(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Capability {
        Capability::new(VId(7), Profile::Agent, &[Op::Read, Op::Post], VId(1))
            .unwrap()
            .with_ceiling(UnitId(0), 100_000)
            .unwrap()
            .expiring_at(CommitSeq(40))
    }

    #[test]
    fn canonical_bytes_round_trip_and_the_commitment_binds_every_caveat() {
        let cap = agent();
        let bytes = cap.canonical_bytes().unwrap();
        assert_eq!(Capability::decode(&bytes).unwrap(), cap);
        let c = cap.commitment().unwrap();
        for other in [
            Capability::new(VId(8), Profile::Agent, &[Op::Read, Op::Post], VId(1)).unwrap(),
            Capability::new(VId(7), Profile::Human, &[Op::Read, Op::Post], VId(1)).unwrap(),
            agent().with_ceiling(UnitId(0), 99_999).unwrap(),
            agent().expiring_at(CommitSeq(39)),
            Capability::new(VId(7), Profile::Agent, &[Op::Read, Op::Post], VId(2)).unwrap(),
        ] {
            assert_ne!(other.commitment().unwrap(), c, "{other:?}");
        }
        // Trailing bytes, unknown tags and truncation are refused.
        let mut long = bytes.clone();
        long.push(0);
        assert!(Capability::decode(&long).is_err());
        assert!(Capability::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut bad_profile = bytes.clone();
        bad_profile[18] = 9;
        assert!(Capability::decode(&bad_profile).is_err());
    }

    #[test]
    fn the_profile_law_holds_for_every_constructor_and_the_decoder() {
        for op in Profile::Agent.forbidden_ops() {
            assert_eq!(
                Capability::new(VId(1), Profile::Agent, &[Op::Post, *op], VId(2)),
                Err(CapabilityError::ForbiddenOp {
                    profile: Profile::Agent,
                    op: *op
                })
            );
        }
        assert!(Capability::new(VId(1), Profile::System, &[Op::Approve], VId(2)).is_err());
        // A Human capability holding approve, re-tagged as Agent on the wire, does not decode.
        let human = Capability::new(VId(1), Profile::Human, &[Op::Approve], VId(2)).unwrap();
        let mut bytes = human.canonical_bytes().unwrap();
        bytes[18] = Profile::Agent.tag();
        assert!(matches!(
            Capability::decode(&bytes),
            Err(CapabilityError::ForbiddenOp { .. })
        ));
    }

    #[test]
    fn embedded_binding_parses_registered_names_and_names_the_nearest_on_a_typo() {
        let cap = Capability::embedded(VId(3), &["post", "post_closed"]).unwrap();
        assert_eq!(cap.profile(), Profile::Human);
        assert_eq!(cap.issuer(), VId(3));
        assert!(cap.holds(Op::PostClosed) && !cap.holds(Op::Close));
        let e = Capability::embedded(VId(3), &["post", "post_clsoed"]).unwrap_err();
        assert_eq!(
            e,
            CapabilityError::UnknownOp {
                name: "post_clsoed".into(),
                nearest: Some(Op::PostClosed)
            }
        );
        assert!(e.to_string().contains("did you mean `post_closed`"));
    }

    #[test]
    fn ceilings_and_expiry_only_tighten() {
        let cap = agent().with_ceiling(UnitId(0), 500_000).unwrap();
        assert_eq!(cap.ceilings().get(&UnitId(0)), Some(&100_000));
        assert_eq!(
            cap.expiring_at(CommitSeq(90)).expires_at(),
            Some(CommitSeq(40))
        );
        assert!(matches!(
            agent().with_ceiling(UnitId(1), 0),
            Err(CapabilityError::BadCeiling { .. })
        ));
    }
}
