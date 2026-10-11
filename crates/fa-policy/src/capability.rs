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

use fa_model::{DecodeError, EncodeError, Id128, Reader, Writer, domain_digest};
use fa_money::UnitId;
use fgdb_types::{CommitSeq, VId};

use crate::op::Op;

pub const CAPABILITY_DOMAIN: &[u8] = b"fa:capability:v1";
/// v1: no caveats beyond ops, ceilings and expiry. v2: v1's fields then a
/// sorted, tagged caveat list (CobaltGull 3251), so each later caveat of
/// plan §14.2 (`redaction`, `accounts`, `periods`, `known_at`, `branch`,
/// `partial_view`) is an additive tag, not a new version. A capability
/// without caveats still encodes as v1, so every commitment minted before
/// caveats existed is unchanged.
const CAPABILITY_VERSION: u16 = 1;
const CAPABILITY_VERSION_CAVEATS: u16 = 2;
/// Caveat tags. A decoder refuses a tag it does not know: a restriction it
/// cannot read is one it cannot enforce, so the token fails closed.
pub const CAVEAT_BOOKS: u8 = 1;
/// Books one capability may name, bounded so a decoder never allocates on a claim.
pub const MAX_BOOKS: usize = 256;
/// Caveats per capability and bytes per caveat payload, bounded likewise.
pub const MAX_CAVEATS: usize = 16;
pub const MAX_CAVEAT_BYTES: usize = 8 * 1024;
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
    /// A books caveat names no book, or more than [`MAX_BOOKS`].
    BadBooks,
    /// A v2 capability carries a caveat tag this build does not know.
    UnknownCaveat {
        tag: u8,
    },
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
            Self::BadBooks => write!(f, "a books caveat names 1..={MAX_BOOKS} books"),
            Self::UnknownCaveat { tag } => write!(
                f,
                "caveat tag {tag} is not known to this build, so the capability cannot be enforced and is refused"
            ),
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
    /// `books ⊆ {…}` (plan §14.2): `None` is no caveat (every book); a
    /// set admits only the books it names.
    books: Option<BTreeSet<Id128>>,
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
            books: None,
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

    /// Confine the capability to `books`. Caveats only narrow: a second call
    /// intersects, and an empty result is refused rather than becoming a
    /// token that admits nothing silently.
    pub fn for_books(mut self, books: &[Id128]) -> Result<Self, CapabilityError> {
        let named: BTreeSet<Id128> = books.iter().copied().collect();
        let next: BTreeSet<Id128> = match self.books.take() {
            Some(held) => held.intersection(&named).copied().collect(),
            None => named,
        };
        if next.is_empty() || next.len() > MAX_BOOKS {
            return Err(CapabilityError::BadBooks);
        }
        self.books = Some(next);
        Ok(self)
    }

    /// The books caveat, when the capability carries one.
    #[must_use]
    pub fn books(&self) -> Option<&BTreeSet<Id128>> {
        self.books.as_ref()
    }

    /// Whether the capability may act on `book`.
    #[must_use]
    pub fn admits_book(&self, book: Id128) -> bool {
        self.books.as_ref().is_none_or(|b| b.contains(&book))
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
    /// ‖ u128 issuer`, then, in v2 only, `‖ list(u8 tag ‖ bytes payload)`,
    /// non-empty and strictly ascending by tag. `books` (tag 1) carries
    /// `list(id128 book, ascending)`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CapabilityError> {
        let ops: Vec<u8> = self.ops.iter().map(|op| op.tag()).collect();
        let ceilings: Vec<(UnitId, i128)> = self.ceilings.iter().map(|(u, m)| (*u, *m)).collect();
        let mut w = Writer::with_capacity(64 + ops.len() + ceilings.len() * 20);
        let version = if self.books.is_some() {
            CAPABILITY_VERSION_CAVEATS
        } else {
            CAPABILITY_VERSION
        };
        w.u16(version)
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
        if let Some(books) = &self.books {
            let books: Vec<Id128> = books.iter().copied().collect();
            let mut payload = Writer::with_capacity(4 + books.len() * 16);
            payload.list(&books, |w, b| {
                w.fixed(&b.0);
            });
            let payload = payload.finish().map_err(CapabilityError::Encode)?;
            let caveats = [(CAVEAT_BOOKS, payload)];
            w.list(&caveats, |w, (tag, payload)| {
                w.u8(*tag).bytes(payload);
            });
        }
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
        if version != CAPABILITY_VERSION && version != CAPABILITY_VERSION_CAVEATS {
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
        let mut books = None;
        if version == CAPABILITY_VERSION_CAVEATS {
            let caveats = r
                .list(MAX_CAVEATS, "capability.caveats", |r| {
                    Ok((
                        r.u8("caveat.tag")?,
                        r.bytes(MAX_CAVEAT_BYTES, "caveat.payload")?.to_vec(),
                    ))
                })
                .map_err(CapabilityError::Decode)?;
            // A v2 without caveats is not canonical: it encodes as v1.
            if caveats.is_empty() {
                return Err(CapabilityError::Decode(r.invalid("capability.caveats")));
            }
            if !caveats.windows(2).all(|w| w[0].0 < w[1].0) {
                return Err(CapabilityError::Decode(r.unsorted("capability.caveats")));
            }
            for (tag, payload) in &caveats {
                match *tag {
                    CAVEAT_BOOKS => books = Some(decode_books(payload)?),
                    tag => return Err(CapabilityError::UnknownCaveat { tag }),
                }
            }
        }
        r.finish().map_err(CapabilityError::Decode)?;
        let mut cap = Self::new(holder, profile, &ops, issuer)?;
        for (unit, max) in ceilings {
            cap = cap.with_ceiling(unit, max)?;
        }
        cap.expires_at = expires_at;
        if let Some(books) = books {
            cap = cap.for_books(&books)?;
        }
        Ok(cap)
    }
}

/// The `books` caveat payload: `list(id128 book, ascending)`, non-empty.
fn decode_books(payload: &[u8]) -> Result<Vec<Id128>, CapabilityError> {
    let mut r = Reader::new(payload);
    let books = r
        .list(MAX_BOOKS, "capability.books", |r| {
            r.fixed("capability.book").map(Id128)
        })
        .map_err(CapabilityError::Decode)?;
    if books.is_empty() {
        return Err(CapabilityError::BadBooks);
    }
    if !books.windows(2).all(|w| w[0] < w[1]) {
        return Err(CapabilityError::Decode(r.unsorted("capability.books")));
    }
    r.finish().map_err(CapabilityError::Decode)?;
    Ok(books)
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

    /// Golden canonical bytes for both minors, written from the documented
    /// layout: v1 carries no `books` caveat and decodes as unrestricted; v2
    /// appends the ascending book list (plan Appendix A additive minor).
    #[test]
    fn capability_bytes_are_golden_for_both_minors() {
        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
                .collect()
        }
        let v1 = hex(concat!(
            "0100",                             // version 1
            "01000000000000000000000000000000", // holder VId(1)
            "00",                               // profile Human
            "01000000",                         // one op:
            "06",                               //   close
            "00000000",                         // no ceilings
            "00",                               // no expiry
            "01000000000000000000000000000000", // issuer VId(1)
        ));
        let cap = Capability::embedded(VId(1), &["close"]).unwrap();
        assert_eq!(cap.canonical_bytes().unwrap(), v1);
        let decoded = Capability::decode(&v1).unwrap();
        assert_eq!(decoded, cap);
        assert!(decoded.books().is_none() && decoded.admits_book(Id128([7; 16])));
        let v2 = hex(concat!(
            "0200",                             // version 2
            "01000000000000000000000000000000", // holder VId(1)
            "00",                               // profile Human
            "01000000",                         // one op:
            "06",                               //   close
            "00000000",                         // no ceilings
            "00",                               // no expiry
            "01000000000000000000000000000000", // issuer VId(1)
            "01000000",                         // one caveat:
            "01",                               //   tag 1, books
            "14000000",                         //   20 payload bytes:
            "01000000",                         //     one book,
            "02020202020202020202020202020202", //     Id128([2; 16])
        ));
        let scoped = cap.for_books(&[Id128([2; 16])]).unwrap();
        assert_eq!(scoped.canonical_bytes().unwrap(), v2);
        assert_eq!(Capability::decode(&v2).unwrap(), scoped);
        assert!(!scoped.admits_book(Id128([7; 16])));
        // Two caveats: books, then tag 2 (`redaction`, fa-txf), which this
        // build does not know yet. The token fails closed rather than
        // decoding as less restricted than it was issued.
        let v2_two = hex(concat!(
            "0200",                             // version 2
            "01000000000000000000000000000000", // holder VId(1)
            "00",                               // profile Human
            "01000000",                         // one op:
            "06",                               //   close
            "00000000",                         // no ceilings
            "00",                               // no expiry
            "01000000000000000000000000000000", // issuer VId(1)
            "02000000",                         // two caveats:
            "01",                               //   tag 1, books
            "14000000",                         //   20 payload bytes:
            "01000000",                         //     one book,
            "02020202020202020202020202020202", //     Id128([2; 16])
            "02",                               //   tag 2
            "00000000",                         //   empty payload
        ));
        assert_eq!(
            Capability::decode(&v2_two),
            Err(CapabilityError::UnknownCaveat { tag: 2 })
        );
        // Tags are strictly ascending, and a v2 names at least one caveat.
        let mut swapped = v2.clone();
        swapped.truncate(v2.len() - 29); // drop the caveat list
        swapped.extend_from_slice(&hex(concat!(
            "02000000",
            "02",
            "00000000",
            "01",
            "14000000",
            "01000000",
            "02020202020202020202020202020202",
        )));
        assert!(matches!(
            Capability::decode(&swapped),
            Err(CapabilityError::Decode(_))
        ));
        let mut bare = v2.clone();
        bare.truncate(v2.len() - 29); // drop the caveat list
        bare.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Capability::decode(&bare),
            Err(CapabilityError::Decode(_))
        ));
    }

    #[test]
    fn the_books_caveat_narrows_round_trips_and_keeps_v1_bytes_when_absent() {
        let plain = Capability::embedded(VId(3), &["post"]).unwrap();
        // Without the caveat the bytes are v1: commitments minted earlier are unchanged.
        assert_eq!(&plain.canonical_bytes().unwrap()[..2], &1u16.to_le_bytes());
        assert!(plain.admits_book(Id128([1; 16])));
        let scoped = plain
            .clone()
            .for_books(&[Id128([2; 16]), Id128([1; 16])])
            .unwrap();
        let bytes = scoped.canonical_bytes().unwrap();
        assert_eq!(&bytes[..2], &2u16.to_le_bytes());
        assert_eq!(Capability::decode(&bytes).unwrap(), scoped);
        assert_ne!(scoped.commitment().unwrap(), plain.commitment().unwrap());
        assert!(scoped.admits_book(Id128([1; 16])) && !scoped.admits_book(Id128([3; 16])));
        // Narrowing intersects; an empty intersection is refused, never a silent no-op token.
        let narrowed = scoped.clone().for_books(&[Id128([2; 16])]).unwrap();
        assert!(!narrowed.admits_book(Id128([1; 16])));
        assert_eq!(
            scoped.for_books(&[Id128([9; 16])]),
            Err(CapabilityError::BadBooks)
        );
        // A books caveat naming no book does not decode.
        let mut empty = plain.canonical_bytes().unwrap();
        empty[..2].copy_from_slice(&2u16.to_le_bytes());
        empty.extend_from_slice(&1u32.to_le_bytes()); // one caveat
        empty.push(CAVEAT_BOOKS);
        empty.extend_from_slice(&4u32.to_le_bytes()); // a 4-byte payload:
        empty.extend_from_slice(&0u32.to_le_bytes()); //   zero books
        assert_eq!(Capability::decode(&empty), Err(CapabilityError::BadBooks));
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
