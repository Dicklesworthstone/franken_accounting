//! The typed capability (plan §14.2, §14.4, Appendix A `Capability`).
//!
//! A capability is a conjunction of caveats held by one principal: the ops
//! it may exercise, per-unit amount and daily-total ceilings, a declared expiry, the
//! profile template it was issued under, and the scope caveats (`books`,
//! `accounts`, `periods`, `effective ≤ date`, `known_at ≤ seq`, `branch`)
//! that [`crate::admit::reach`] judges. It is a value with canonical bytes
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
//! **Daily ceilings share one issuance root.** `daily_total ≤ A` bounds
//! gross debit mantissas per unit over a book calendar day. The kernel
//! derives that day from retained time evidence and charges the root's
//! journal-backed usage in the posting transaction. This value carries the
//! limits and the immutable inherited root, never a caller-reported balance.
//!
//! **Trust boundary.** This crate decides whether a capability authorizes
//! an act; it does not decide whether the caller holds the capability. In
//! the embedded posture [`Capability::embedded`] self-issues under the
//! calling process's authority. MCP binds a capability from trusted launch
//! configuration; it does not authenticate the named principal. Journaled
//! issuance and authenticated holder-bound sessions remain separate work.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use fa_model::{DecodeError, EncodeError, EntryClass, Id128, Reader, Writer, domain_digest};
use fa_money::UnitId;
use fa_registry::redaction_contracts::RedactionContracts;
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::op::Op;

pub const CAPABILITY_DOMAIN: &[u8] = b"fa:capability:v1";
/// v1: no caveats beyond ops, ceilings and expiry. v2: v1's fields then a
/// sorted, tagged caveat list (CobaltGull 3251), so each later caveat of
/// plan §14.2 is an additive tag, not a new version. A capability without
/// caveats still encodes as v1, so every commitment minted before caveats
/// existed is unchanged. (`partial_view` is an op, not a caveat.)
const CAPABILITY_VERSION: u16 = 1;
const CAPABILITY_VERSION_CAVEATS: u16 = 2;
/// Caveat tags. A decoder refuses a tag it does not know: a restriction it
/// cannot read is one it cannot enforce, so the token fails closed.
pub const CAVEAT_BOOKS: u8 = 1;
/// `redaction = <contract>`: `u16` registered contract id (fa-kuu).
pub const CAVEAT_REDACTION: u8 = 2;
/// `accounts ⊆ subtree(code)`: `list(str code, ascending)`.
pub const CAVEAT_ACCOUNTS: u8 = 3;
/// `periods ⊆ {…}`: `list(str period code, ascending)`.
pub const CAVEAT_PERIODS: u8 = 4;
/// `effective ≤ date`: `i32 day`.
pub const CAVEAT_EFFECTIVE: u8 = 5;
/// `known_at ≤ seq`: `u64 seq`.
pub const CAVEAT_KNOWN_AT: u8 = 6;
/// `branch = <draft>`: `id128 branch`.
pub const CAVEAT_BRANCH: u8 = 7;
/// `possession = H(secret)` (plan §14.2, bead fa-v62): `[u8; 32]`, the
/// [`possession_digest`] of the holder's secret. A holder-bound capability
/// is an *issued* token: the kernel admits it only with its journaled
/// issuance, and its holder proves possession of the secret.
pub const CAVEAT_POSSESSION: u8 = 8;
/// `daily_total ≤ A` per unit: non-empty `list(u32 unit, i128 max)`,
/// ascending by unit, with positive mantissas (plan §14.2).
pub const CAVEAT_DAILY_TOTALS: u8 = 9;
/// The inherited daily quota root: the canonical commitment of the root
/// issuance, `[u8; 32]`. Absent on a root issuance, whose own commitment
/// identifies its quota; present on descendants and validated by the kernel.
pub const CAVEAT_DAILY_ROOT: u8 = 10;
/// `operator_kind = 1` (Agent): `u8` operator kind tag (`1`), emitted when a
/// `Human`-profile capability is held by an AI operator (e.g. MCP `Preparer`,
/// plan §14.4, bead fa-5npo).
pub const CAVEAT_OPERATOR_KIND: u8 = 11;
/// `requires_dry_run = true`: `u8` (`1`), emitted when a non-`Agent`
/// capability requires rehearsal before any write commit (plan §14.2, §14.4).
pub const CAVEAT_REQUIRES_DRY_RUN: u8 = 12;
/// `classes ⊆ EntryClass`: non-empty `list(u16 class_tag, ascending)` (plan §14.2).
pub const CAVEAT_CLASSES: u8 = 13;
/// Domain of [`possession_digest`].
pub const POSSESSION_DOMAIN: &[u8] = b"fa:capability-possession:v1";

/// The digest a holder-bound capability carries for `secret`.
#[must_use]
pub fn possession_digest(secret: &[u8; 32]) -> [u8; 32] {
    domain_digest(POSSESSION_DOMAIN, &[secret])
}
/// Books one capability may name, bounded so a decoder never allocates on a claim.
pub const MAX_BOOKS: usize = 256;
/// Subtree roots an `accounts` caveat may name, and bytes per account code
/// (Appendix A `Account.code`).
pub const MAX_ACCOUNT_ROOTS: usize = 64;
pub const MAX_ACCOUNT_CODE_BYTES: usize = 64;
/// Periods a `periods` caveat may name, and bytes per period code.
pub const MAX_PERIODS: usize = 256;
pub const MAX_PERIOD_CODE_BYTES: usize = 64;
/// Caveats per capability and bytes per caveat payload, bounded likewise.
pub const MAX_CAVEATS: usize = 16;
pub const MAX_CAVEAT_BYTES: usize = 8 * 1024;
/// Ceilings per capability, bounded so a decoder never allocates on a claim.
pub const MAX_CEILINGS: usize = 256;
/// Units a daily-total caveat may bound, checked before decoder allocation.
pub const MAX_DAILY_TOTALS: usize = 256;
/// Classes a `classes` caveat may name, checked before decoder allocation.
pub const MAX_CLASSES: usize = 64;

/// Whether a capability's operator is a human or an AI agent (plan §14.4).
///
/// A `Human`-profile capability held by an MCP `Preparer` carries
/// `OperatorKind::Agent`: it retains the `Preparer` op ceiling (`post_softclosed`
/// etc.), but SoD (`agent_prepared_human_approvers`) and document upload grading
/// (`AgentUpload`) treat work performed under it as agent-prepared rather than
/// human-authored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperatorKind {
    Human,
    Agent,
}

impl OperatorKind {
    pub const ALL: [Self; 2] = [Self::Human, Self::Agent];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Human => "Human",
            Self::Agent => "Agent",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Human" | "human" => Some(Self::Human),
            "Agent" | "agent" => Some(Self::Agent),
            _ => None,
        }
    }

    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Human => 0,
            Self::Agent => 1,
        }
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.tag() == tag)
    }
}

impl fmt::Display for OperatorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The ten registered profile templates of plan §14.4 (`capability_caveats.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileTemplate {
    Agent,
    Preparer,
    Approver,
    Controller,
    Auditor,
    Regulator,
    Investigator,
    Receiver,
    Production,
    Witness,
}

impl ProfileTemplate {
    pub const ALL: [Self; 10] = [
        Self::Agent,
        Self::Preparer,
        Self::Approver,
        Self::Controller,
        Self::Auditor,
        Self::Regulator,
        Self::Investigator,
        Self::Receiver,
        Self::Production,
        Self::Witness,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Agent => "Agent",
            Self::Preparer => "Preparer",
            Self::Approver => "Approver",
            Self::Controller => "Controller",
            Self::Auditor => "Auditor",
            Self::Regulator => "Regulator",
            Self::Investigator => "Investigator",
            Self::Receiver => "Receiver",
            Self::Production => "Production",
            Self::Witness => "Witness",
        }
    }

    #[must_use]
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Preparer => "preparer",
            Self::Approver => "approver",
            Self::Controller => "controller",
            Self::Auditor => "auditor",
            Self::Regulator => "regulator",
            Self::Investigator => "investigator",
            Self::Receiver => "receiver",
            Self::Production => "production",
            Self::Witness => "witness",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|t| t.name() == name || t.cli_name() == name)
    }

    #[must_use]
    pub fn base_profile(self) -> Profile {
        match self {
            Self::Agent => Profile::Agent,
            Self::Preparer
            | Self::Approver
            | Self::Controller
            | Self::Auditor
            | Self::Regulator
            | Self::Investigator
            | Self::Receiver
            | Self::Production
            | Self::Witness => Profile::Human,
        }
    }

    #[must_use]
    pub fn default_operator_kind(self) -> OperatorKind {
        match self {
            Self::Agent => OperatorKind::Agent,
            Self::Preparer
            | Self::Approver
            | Self::Controller
            | Self::Auditor
            | Self::Regulator
            | Self::Investigator
            | Self::Receiver
            | Self::Production
            | Self::Witness => OperatorKind::Human,
        }
    }

    #[must_use]
    pub fn is_external(self) -> bool {
        matches!(
            self,
            Self::Auditor
                | Self::Regulator
                | Self::Investigator
                | Self::Receiver
                | Self::Production
                | Self::Witness
        )
    }

    #[must_use]
    pub fn ops_ceiling(self) -> &'static [Op] {
        match self {
            Self::Agent => &[
                Op::Read,
                Op::Post,
                Op::Reconcile,
                Op::Verify,
                Op::Produce,
                Op::PartialView,
            ],
            Self::Preparer => &[
                Op::Read,
                Op::Post,
                Op::PostSoftclosed,
                Op::Reconcile,
                Op::Verify,
                Op::Produce,
                Op::PartialView,
            ],
            Self::Approver => &[
                Op::Read,
                Op::Post,
                Op::PostSoftclosed,
                Op::PostClosed,
                Op::Approve,
                Op::Reconcile,
                Op::Verify,
                Op::Produce,
                Op::PartialView,
            ],
            Self::Controller => &[
                Op::Read,
                Op::Post,
                Op::PostSoftclosed,
                Op::PostClosed,
                Op::Approve,
                Op::Reconcile,
                Op::Close,
                Op::Reopen,
                Op::Restate,
                Op::Migrate,
                Op::SchemaChange,
                Op::RuleChange,
                Op::IssueCapability,
                Op::Verify,
                Op::Produce,
                Op::Hold,
                Op::Erase,
                Op::Privileged,
                Op::PartialView,
            ],
            Self::Auditor => &[
                Op::Read,
                Op::Verify,
                Op::Produce,
                Op::Witness,
                Op::PartialView,
            ],
            Self::Regulator => &[Op::Read, Op::Verify, Op::Produce, Op::PartialView],
            Self::Investigator => &[
                Op::Read,
                Op::Verify,
                Op::Produce,
                Op::Hold,
                Op::Privileged,
                Op::PartialView,
            ],
            Self::Receiver => &[
                Op::Read,
                Op::Post,
                Op::PostSoftclosed,
                Op::PostClosed,
                Op::Approve,
                Op::Reconcile,
                Op::Close,
                Op::Reopen,
                Op::Restate,
                Op::SchemaChange,
                Op::RuleChange,
                Op::IssueCapability,
                Op::Verify,
                Op::Produce,
                Op::Hold,
                Op::Receivership,
                Op::PartialView,
            ],
            Self::Production => &[Op::Read, Op::Verify, Op::Produce],
            Self::Witness => &[Op::Read, Op::Verify, Op::Witness],
        }
    }

    #[must_use]
    pub fn default_ops(self) -> &'static [Op] {
        match self {
            Self::Agent | Self::Preparer => &[Op::Read, Op::Post, Op::Verify],
            Self::Approver => &[Op::Read, Op::Approve, Op::Verify],
            Self::Controller => &[
                Op::Read,
                Op::Post,
                Op::PostSoftclosed,
                Op::PostClosed,
                Op::Approve,
                Op::Reconcile,
                Op::Close,
                Op::Reopen,
                Op::Restate,
                Op::SchemaChange,
                Op::RuleChange,
                Op::IssueCapability,
                Op::Verify,
                Op::Produce,
            ],
            Self::Auditor => &[Op::Read, Op::Verify, Op::Produce, Op::Witness],
            Self::Regulator => &[Op::Read, Op::Verify, Op::Produce],
            Self::Investigator => &[Op::Read, Op::Verify, Op::Produce, Op::Hold],
            Self::Receiver => &[
                Op::Read,
                Op::Post,
                Op::Reconcile,
                Op::Close,
                Op::Verify,
                Op::Produce,
                Op::Hold,
                Op::Receivership,
            ],
            Self::Production => &[Op::Read, Op::Produce],
            Self::Witness => &[Op::Witness],
        }
    }

    #[must_use]
    pub fn required_caveats(self) -> &'static [&'static str] {
        match self {
            Self::Agent | Self::Preparer | Self::Approver | Self::Controller => &["ops"],
            Self::Auditor => &["ops", "books", "redaction"],
            Self::Regulator => &["ops", "books", "expires_at", "redaction"],
            Self::Investigator => &["ops", "books", "expires_at"],
            Self::Receiver | Self::Witness => &["ops", "books"],
            Self::Production => &["ops", "books", "known_at", "redaction", "expires_at"],
        }
    }

    /// Check that `cap` satisfies this template's base profile, ops ceiling,
    /// and required caveats (`capability_caveats.toml`).
    pub fn validate_capability(self, cap: &Capability) -> Result<(), CapabilityError> {
        if cap.profile() != self.base_profile() {
            return Err(CapabilityError::BadOperatorKind);
        }
        if self != Self::Agent
            && self != Self::Preparer
            && cap.operator_kind() != OperatorKind::Human
        {
            return Err(CapabilityError::BadOperatorKind);
        }
        let ceiling = self.ops_ceiling();
        for op in cap.ops() {
            if !ceiling.contains(op) {
                return Err(CapabilityError::TemplateForbiddenOp {
                    template: self,
                    op: *op,
                });
            }
        }
        for cav in self.required_caveats() {
            let present = match *cav {
                "ops" => !cap.ops().is_empty(),
                "books" => cap.books().is_some(),
                "redaction" => cap.redaction().is_some(),
                "expires_at" => cap.expires_at().is_some(),
                "known_at" => cap.known_at_pin().is_some(),
                "branch" => cap.branch().is_some(),
                "requires_dry_run" => cap.requires_dry_run(),
                _ => true,
            };
            if !present {
                return Err(CapabilityError::MissingTemplateCaveat {
                    template: self,
                    caveat: cav,
                });
            }
        }
        Ok(())
    }
}

impl fmt::Display for ProfileTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

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
    /// An op is outside the named profile template's `ops_ceiling` (plan §14.4).
    TemplateForbiddenOp {
        template: ProfileTemplate,
        op: Op,
    },
    /// A profile template requires a caveat that the capability omits (plan §14.4).
    MissingTemplateCaveat {
        template: ProfileTemplate,
        caveat: &'static str,
    },
    /// `operator_kind` is non-canonical or would escalate an Agent operator to Human.
    BadOperatorKind,
    /// `requires_dry_run` is non-canonical (e.g. redundant on `Profile::Agent`).
    BadRequiresDryRun,
    /// A `classes` caveat names no class, more than [`MAX_CLASSES`], or an unknown class tag.
    BadClasses,
    /// A ceiling must be a positive mantissa.
    BadCeiling {
        unit: UnitId,
        max_mantissa: i128,
    },
    TooManyCeilings,
    /// A daily-total ceiling must be a positive mantissa.
    BadDailyTotal {
        unit: UnitId,
        max_mantissa: i128,
    },
    TooManyDailyTotals,
    /// A daily root requires daily totals and cannot be moved to a second root.
    BadDailyRoot,
    /// A books caveat names no book, or more than [`MAX_BOOKS`].
    BadBooks,
    /// A redaction caveat names an unregistered contract id, or would move a
    /// redaction-confined token to a second contract.
    BadRedaction {
        contract: u16,
    },
    /// An accounts caveat names no root, more than [`MAX_ACCOUNT_ROOTS`],
    /// or a code outside 1..=[`MAX_ACCOUNT_CODE_BYTES`] bytes.
    BadAccounts,
    /// A periods caveat names no period, more than [`MAX_PERIODS`], or a
    /// code outside 1..=[`MAX_PERIOD_CODE_BYTES`] bytes.
    BadPeriods,
    /// A branch caveat would confine the token to a second branch.
    BadBranch,
    /// A v2 capability carries a caveat tag this build does not know.
    UnknownCaveat {
        tag: u8,
    },
    Decode(DecodeError),
    Encode(EncodeError),
    /// A capability token file that does not hold together (bead fa-v62).
    BadToken(&'static str),
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
            Self::TemplateForbiddenOp { template, op } => {
                write!(
                    f,
                    "the `{template}` profile template can never hold `{op}` (plan §14.4)"
                )
            }
            Self::MissingTemplateCaveat { template, caveat } => {
                write!(
                    f,
                    "the `{template}` profile template requires caveat `{caveat}` (plan §14.4)"
                )
            }
            Self::BadOperatorKind => {
                write!(
                    f,
                    "invalid operator_kind caveat: an AI operator cannot escalate to Human, and Agent/System base profiles are already Agent operators"
                )
            }
            Self::BadRequiresDryRun => {
                write!(
                    f,
                    "invalid requires_dry_run caveat: payload must be 1 on a non-Agent profile"
                )
            }
            Self::BadClasses => {
                write!(
                    f,
                    "a classes caveat names 1..={MAX_CLASSES} registered EntryClass values, and narrowing keeps at least one held class"
                )
            }
            Self::BadCeiling { unit, max_mantissa } => write!(
                f,
                "ceiling {max_mantissa} for unit {} is not a positive mantissa",
                unit.0
            ),
            Self::TooManyCeilings => write!(f, "more than {MAX_CEILINGS} ceilings"),
            Self::BadDailyTotal { unit, max_mantissa } => write!(
                f,
                "daily-total ceiling {max_mantissa} for unit {} is not a positive mantissa",
                unit.0
            ),
            Self::TooManyDailyTotals => {
                write!(f, "more than {MAX_DAILY_TOTALS} daily-total ceilings")
            }
            Self::BadDailyRoot => write!(
                f,
                "a daily quota root requires daily-total ceilings and cannot be changed once inherited"
            ),
            Self::BadBooks => write!(f, "a books caveat names 1..={MAX_BOOKS} books"),
            Self::BadRedaction { contract } => write!(
                f,
                "a redaction caveat names one registered redaction contract (`redaction_contracts.toml`); contract {contract} is unregistered or conflicts with a held contract"
            ),
            Self::BadAccounts => write!(
                f,
                "an accounts caveat names 1..={MAX_ACCOUNT_ROOTS} subtree roots of 1..={MAX_ACCOUNT_CODE_BYTES} bytes, and narrowing keeps at least one held root"
            ),
            Self::BadPeriods => write!(
                f,
                "a periods caveat names 1..={MAX_PERIODS} periods of 1..={MAX_PERIOD_CODE_BYTES} bytes, and narrowing keeps at least one held period"
            ),
            Self::BadBranch => write!(
                f,
                "a branch caveat confines the token to one branch; it cannot be moved to another"
            ),
            Self::UnknownCaveat { tag } => write!(
                f,
                "caveat tag {tag} is not known to this build, so the capability cannot be enforced and is refused"
            ),
            Self::Decode(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::BadToken(why) => write!(f, "invalid capability token: {why}"),
        }
    }
}

impl core::error::Error for CapabilityError {}

fn redaction_contracts() -> &'static RedactionContracts {
    static CONTRACTS: OnceLock<RedactionContracts> = OnceLock::new();
    CONTRACTS.get_or_init(|| {
        RedactionContracts::embedded().expect("embedded redaction_contracts.toml must be valid")
    })
}

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
    /// `redaction = <contract>` (plan §9.6, §14.2, fa-kuu): confines the
    /// capability to the named registered contract's redacted views for the
    /// documents that contract governs, even if the capability also holds
    /// `privileged`.
    redaction: Option<u16>,
    /// `accounts ⊆ subtree(code)`: the roots by account code, resolved per
    /// book by the kernel (the root and its `CHILD_OF` descendants).
    accounts: Option<BTreeSet<String>>,
    /// `periods ⊆ {…}`, by period code.
    periods: Option<BTreeSet<String>>,
    /// `effective ≤ date`: the last effective day the token reaches.
    effective_through: Option<DateDay>,
    /// `known_at ≤ seq`: the last recorded frontier the token observes. A
    /// pinned token never writes (a write observes the head).
    known_at: Option<CommitSeq>,
    /// `branch = <draft>`: the one branch the token acts on.
    branch: Option<Id128>,
    /// `possession = H(secret)`: the token is issued and holder-bound.
    possession: Option<[u8; 32]>,
    /// Gross debit mantissas per book calendar day, per unit, shared across
    /// a root issuance and all its descendants. A non-empty map permits
    /// only the units it bounds, as enforced by the posting kernel.
    daily_totals: BTreeMap<UnitId, i128>,
    /// The inherited root issuance's commitment. `None` with daily totals
    /// means this capability is a root; the kernel validates that issuance.
    daily_root: Option<[u8; 32]>,
    /// Operator provenance kind (`Human` or `Agent`, plan §14.4): an MCP
    /// `Preparer` has `profile == Profile::Human` (so it can hold
    /// `post_softclosed`) and `operator_kind == OperatorKind::Agent` (so SoD
    /// and upload grading record an AI operator, never a human).
    operator_kind: OperatorKind,
    /// `requires_dry_run = true` caveat on a non-`Agent` capability.
    requires_dry_run: bool,
    /// `classes ⊆ EntryClass` caveat (`None` admits every class).
    classes: Option<BTreeSet<EntryClass>>,
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
        let operator_kind = match profile {
            Profile::Human => OperatorKind::Human,
            Profile::Agent | Profile::System => OperatorKind::Agent,
        };
        Ok(Self {
            holder,
            profile,
            ops,
            ceilings: BTreeMap::new(),
            expires_at: None,
            issuer,
            books: None,
            redaction: None,
            accounts: None,
            periods: None,
            effective_through: None,
            known_at: None,
            branch: None,
            possession: None,
            daily_totals: BTreeMap::new(),
            daily_root: None,
            operator_kind,
            requires_dry_run: false,
            classes: None,
        })
    }

    /// Construct a capability from a registered §14.4 [`ProfileTemplate`],
    /// defaulting `ops` to [`ProfileTemplate::default_ops`] when `None` and
    /// refusing any op outside [`ProfileTemplate::ops_ceiling`].
    pub fn from_template(
        holder: VId,
        template: ProfileTemplate,
        ops: Option<&[Op]>,
        issuer: VId,
    ) -> Result<Self, CapabilityError> {
        let ops = ops.unwrap_or_else(|| template.default_ops());
        if ops.is_empty() {
            return Err(CapabilityError::MissingTemplateCaveat {
                template,
                caveat: "ops",
            });
        }
        let ceiling = template.ops_ceiling();
        for op in ops {
            if !ceiling.contains(op) {
                return Err(CapabilityError::TemplateForbiddenOp { template, op: *op });
            }
        }
        Self::new(holder, template.base_profile(), ops, issuer)
    }

    /// Validate that this capability satisfies `template`'s base profile,
    /// ops ceiling, and required caveats (`capability_caveats.toml`).
    pub fn validate_template(&self, template: ProfileTemplate) -> Result<(), CapabilityError> {
        template.validate_capability(self)
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

    /// Add a unit's daily-total ceiling, or tighten its existing bound.
    /// Like [`Self::with_ceiling`], this constructs a proposed grant; the
    /// kernel checks that issuance never adds units outside an issuer's
    /// bounded set, drops its limits, or resets its inherited quota root.
    pub fn with_daily_total(
        mut self,
        unit: UnitId,
        max_mantissa: i128,
    ) -> Result<Self, CapabilityError> {
        if max_mantissa <= 0 {
            return Err(CapabilityError::BadDailyTotal { unit, max_mantissa });
        }
        let slot = self.daily_totals.entry(unit).or_insert(max_mantissa);
        *slot = (*slot).min(max_mantissa);
        if self.daily_totals.len() > MAX_DAILY_TOTALS {
            return Err(CapabilityError::TooManyDailyTotals);
        }
        Ok(self)
    }

    /// Bind daily totals to an inherited root, preserving it on every
    /// later narrowing. A root cannot stand alone or be replaced. The
    /// kernel verifies that this commitment is the issuer's actual quota
    /// root; naming a commitment here does not prove that lineage.
    pub fn with_daily_root(mut self, root: [u8; 32]) -> Result<Self, CapabilityError> {
        if self.daily_totals.is_empty() || self.daily_root.is_some_and(|held| held != root) {
            return Err(CapabilityError::BadDailyRoot);
        }
        self.daily_root = Some(root);
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

    /// Confine the capability to the redacted views of registered `contract`
    /// (`redaction_contracts.toml`) for the documents that contract governs,
    /// conjunctive with `privileged` (plan §9.6, §14.2, fa-kuu). Repeating the
    /// same contract is a no-op; naming an unregistered contract or another
    /// contract is refused.
    pub fn with_redaction(mut self, contract: u16) -> Result<Self, CapabilityError> {
        if redaction_contracts().get(contract).is_none() {
            return Err(CapabilityError::BadRedaction { contract });
        }
        match self.redaction {
            Some(held) if held != contract => Err(CapabilityError::BadRedaction { contract }),
            _ => {
                self.redaction = Some(contract);
                Ok(self)
            }
        }
    }

    /// The `redaction = <contract>` caveat, when the capability carries one.
    #[must_use]
    pub fn redaction(&self) -> Option<u16> {
        self.redaction
    }

    /// Whether the capability reveals the privileged bytes of a document
    /// governed by `contract`: it holds `privileged` and is not confined to
    /// `contract`'s redacted views by a `redaction` caveat.
    #[must_use]
    pub fn reveals_contract(&self, contract: u16) -> bool {
        self.holds(Op::Privileged) && self.redaction != Some(contract)
    }

    /// Confine the capability to the subtrees rooted at `codes`. A second
    /// call keeps only the roots both name: subtree containment needs the
    /// chart, which this crate never reads, so narrowing to a descendant
    /// root is a fresh issuance, not an attenuation. An empty result is
    /// refused.
    pub fn for_accounts(mut self, codes: &[&str]) -> Result<Self, CapabilityError> {
        let named = bounded_codes(codes, MAX_ACCOUNT_ROOTS, MAX_ACCOUNT_CODE_BYTES)
            .ok_or(CapabilityError::BadAccounts)?;
        self.accounts =
            Some(narrow(self.accounts.take(), named).ok_or(CapabilityError::BadAccounts)?);
        Ok(self)
    }

    /// Confine the capability to the periods `codes` names; a second call
    /// intersects, and an empty result is refused.
    pub fn for_periods(mut self, codes: &[&str]) -> Result<Self, CapabilityError> {
        let named = bounded_codes(codes, MAX_PERIODS, MAX_PERIOD_CODE_BYTES)
            .ok_or(CapabilityError::BadPeriods)?;
        self.periods = Some(narrow(self.periods.take(), named).ok_or(CapabilityError::BadPeriods)?);
        Ok(self)
    }

    /// Confine the capability to effective dates `≤ day`; a second call can
    /// only tighten it.
    #[must_use]
    pub fn effective_through(mut self, day: DateDay) -> Self {
        self.effective_through = Some(self.effective_through.map_or(day, |d| d.min(day)));
        self
    }

    /// Pin the capability to recorded frontiers `≤ seq`; a second call can
    /// only tighten it.
    #[must_use]
    pub fn known_at_most(mut self, seq: CommitSeq) -> Self {
        self.known_at = Some(self.known_at.map_or(seq, |k| k.min(seq)));
        self
    }

    /// Confine the capability to `branch`. Repeating the same branch is a
    /// no-op; naming another is refused (the conjunction would admit
    /// nothing).
    pub fn on_branch(mut self, branch: Id128) -> Result<Self, CapabilityError> {
        match self.branch {
            Some(held) if held != branch => Err(CapabilityError::BadBranch),
            _ => {
                self.branch = Some(branch);
                Ok(self)
            }
        }
    }

    /// The `accounts` caveat's subtree roots, when the capability carries one.
    #[must_use]
    pub fn accounts(&self) -> Option<&BTreeSet<String>> {
        self.accounts.as_ref()
    }

    /// The `periods` caveat, when the capability carries one.
    #[must_use]
    pub fn periods(&self) -> Option<&BTreeSet<String>> {
        self.periods.as_ref()
    }

    /// The `effective ≤ date` caveat, when the capability carries one.
    #[must_use]
    pub fn effective_bound(&self) -> Option<DateDay> {
        self.effective_through
    }

    /// The `known_at ≤ seq` pin, when the capability carries one.
    #[must_use]
    pub fn known_at_pin(&self) -> Option<CommitSeq> {
        self.known_at
    }

    /// The `branch` caveat, when the capability carries one.
    #[must_use]
    pub fn branch(&self) -> Option<Id128> {
        self.branch
    }

    /// Bind the capability to a holder secret by its [`possession_digest`]
    /// (an issued token, plan §14.2). The digest is part of the commitment,
    /// so the binding cannot be removed or swapped without a new issuance.
    #[must_use]
    pub fn holder_bound(mut self, digest: [u8; 32]) -> Self {
        self.possession = Some(digest);
        self
    }

    /// The possession digest of a holder-bound (issued) capability.
    #[must_use]
    pub fn possession(&self) -> Option<[u8; 32]> {
        self.possession
    }

    /// Whether `secret` proves possession of this holder-bound capability.
    /// An unbound capability proves nothing.
    #[must_use]
    pub fn proves_possession(&self, secret: &[u8; 32]) -> bool {
        let presented = possession_digest(secret);
        self.possession.is_some_and(|digest| {
            // Constant time over the whole digest: no early exit leaks a prefix.
            digest
                .iter()
                .zip(presented.iter())
                .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
                == 0
        })
    }

    /// Whether any scope caveat beyond `books` confines the capability: such
    /// a token reaches only what [`crate::admit::reach`] admits, so an act
    /// on the whole book refuses it.
    #[must_use]
    pub fn is_scoped(&self) -> bool {
        self.accounts.is_some()
            || self.periods.is_some()
            || self.effective_through.is_some()
            || self.known_at.is_some()
            || self.branch.is_some()
    }

    #[must_use]
    pub fn holder(&self) -> VId {
        self.holder
    }

    #[must_use]
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The operator provenance kind (`Human` or `Agent`, plan §14.4).
    #[must_use]
    pub fn operator_kind(&self) -> OperatorKind {
        self.operator_kind
    }

    /// The effective profile for SoD (`agent_prepared_human_approvers`) and
    /// document upload grading (`AgentUpload` vs `Unreviewed`): an MCP
    /// `Preparer` (`Profile::Human` + `OperatorKind::Agent`) evaluates as
    /// `Profile::Agent` so its work is recorded as AI-prepared, never human.
    #[must_use]
    pub fn sod_profile(&self) -> Profile {
        if self.profile == Profile::Human && self.operator_kind == OperatorKind::Agent {
            Profile::Agent
        } else {
            self.profile
        }
    }

    /// Narrow or set `operator_kind` (monotone `Human -> Agent`, plan §14.4).
    /// Setting `OperatorKind::Agent` refuses any op in
    /// `Profile::Agent.forbidden_ops()`; attempting to set `OperatorKind::Human`
    /// on an `Agent` or `System` capability (or after `OperatorKind::Agent`
    /// was already set) is refused.
    pub fn with_operator_kind(mut self, kind: OperatorKind) -> Result<Self, CapabilityError> {
        match kind {
            OperatorKind::Human => {
                if self.profile != Profile::Human || self.operator_kind != OperatorKind::Human {
                    return Err(CapabilityError::BadOperatorKind);
                }
                Ok(self)
            }
            OperatorKind::Agent => {
                if let Some(op) = Profile::Agent
                    .forbidden_ops()
                    .iter()
                    .find(|op| self.ops.contains(op))
                {
                    return Err(CapabilityError::ForbiddenOp {
                        profile: Profile::Agent,
                        op: *op,
                    });
                }
                self.operator_kind = OperatorKind::Agent;
                Ok(self)
            }
        }
    }

    /// Require a rehearsal dry-run certificate before any write commit.
    #[must_use]
    pub fn with_requires_dry_run(mut self) -> Self {
        if self.profile != Profile::Agent {
            self.requires_dry_run = true;
        }
        self
    }

    /// Whether the capability requires rehearsal (`true` for `Profile::Agent`
    /// or when the `requires_dry_run` caveat is set).
    #[must_use]
    pub fn requires_dry_run(&self) -> bool {
        self.requires_dry_run || self.profile == Profile::Agent
    }

    /// Whether the capability explicitly carries the `requires_dry_run` caveat
    /// tag (`tag = 12`).
    #[must_use]
    pub fn has_requires_dry_run_caveat(&self) -> bool {
        self.requires_dry_run
    }

    /// Confine the capability to the entry classes in `classes`; a second call
    /// intersects, and an empty intersection is refused.
    pub fn for_classes(mut self, classes: &[EntryClass]) -> Result<Self, CapabilityError> {
        if classes.is_empty() || classes.len() > MAX_CLASSES {
            return Err(CapabilityError::BadClasses);
        }
        let named: BTreeSet<EntryClass> = classes.iter().copied().collect();
        self.classes = Some(narrow(self.classes.take(), named).ok_or(CapabilityError::BadClasses)?);
        Ok(self)
    }

    /// The `classes` caveat, when the capability carries one.
    #[must_use]
    pub fn classes(&self) -> Option<&BTreeSet<EntryClass>> {
        self.classes.as_ref()
    }

    /// Whether the capability admits `class`.
    #[must_use]
    pub fn admits_class(&self, class: EntryClass) -> bool {
        self.classes.as_ref().is_none_or(|c| c.contains(&class))
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
    pub fn daily_totals(&self) -> &BTreeMap<UnitId, i128> {
        &self.daily_totals
    }

    /// The inherited root, or `None` for an independently issued root or
    /// a capability without daily-total limits.
    #[must_use]
    pub fn daily_root(&self) -> Option<[u8; 32]> {
        self.daily_root
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
    /// non-empty and strictly ascending by tag. Payloads: `books` (1)
    /// `list(id128 book, ascending)`; `redaction` (2) `u16 contract`;
    /// `accounts` (3) and `periods` (4) `list(str code, ascending)`;
    /// `effective` (5) `i32 day`; `known_at` (6) `u64 seq`; `branch` (7)
    /// `id128 branch`; `possession` (8) `[u8; 32]`; `daily_totals` (9)
    /// `list(u32 unit, i128 max, ascending by unit)`; `daily_root` (10)
    /// `[u8; 32]`, only with non-empty `daily_totals`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CapabilityError> {
        let ops: Vec<u8> = self.ops.iter().map(|op| op.tag()).collect();
        let ceilings: Vec<(UnitId, i128)> = self.ceilings.iter().map(|(u, m)| (*u, *m)).collect();
        let caveats = self.caveats()?;
        let mut w = Writer::with_capacity(64 + ops.len() + ceilings.len() * 20);
        let version = if caveats.is_empty() {
            CAPABILITY_VERSION
        } else {
            CAPABILITY_VERSION_CAVEATS
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
        if !caveats.is_empty() {
            w.list(&caveats, |w, (tag, payload)| {
                w.u8(*tag).bytes(payload);
            });
        }
        w.finish().map_err(CapabilityError::Encode)
    }

    /// The v2 caveat list `(tag, payload)`, ascending by tag.
    fn caveats(&self) -> Result<Vec<(u8, Vec<u8>)>, CapabilityError> {
        let mut out = Vec::new();
        if let Some(books) = &self.books {
            let books: Vec<Id128> = books.iter().copied().collect();
            let mut payload = Writer::with_capacity(4 + books.len() * 16);
            payload.list(&books, |w, b| {
                w.fixed(&b.0);
            });
            out.push((
                CAVEAT_BOOKS,
                payload.finish().map_err(CapabilityError::Encode)?,
            ));
        }
        if let Some(contract) = self.redaction {
            let mut payload = Writer::with_capacity(2);
            payload.u16(contract);
            out.push((
                CAVEAT_REDACTION,
                payload.finish().map_err(CapabilityError::Encode)?,
            ));
        }
        if let Some(accounts) = &self.accounts {
            out.push((CAVEAT_ACCOUNTS, encode_codes(accounts)?));
        }
        if let Some(periods) = &self.periods {
            out.push((CAVEAT_PERIODS, encode_codes(periods)?));
        }
        if let Some(day) = self.effective_through {
            let mut payload = Writer::with_capacity(4);
            payload.i32(day.0);
            out.push((
                CAVEAT_EFFECTIVE,
                payload.finish().map_err(CapabilityError::Encode)?,
            ));
        }
        if let Some(seq) = self.known_at {
            let mut payload = Writer::with_capacity(8);
            payload.u64(seq.0);
            out.push((
                CAVEAT_KNOWN_AT,
                payload.finish().map_err(CapabilityError::Encode)?,
            ));
        }
        if let Some(branch) = self.branch {
            let mut payload = Writer::with_capacity(16);
            payload.fixed(&branch.0);
            out.push((
                CAVEAT_BRANCH,
                payload.finish().map_err(CapabilityError::Encode)?,
            ));
        }
        if let Some(digest) = self.possession {
            out.push((CAVEAT_POSSESSION, digest.to_vec()));
        }
        if !self.daily_totals.is_empty() {
            let totals: Vec<(UnitId, i128)> =
                self.daily_totals.iter().map(|(u, m)| (*u, *m)).collect();
            let mut payload = Writer::with_capacity(4 + totals.len() * 20);
            payload.list(&totals, |w, (u, m)| {
                w.u32(u.0).i128(*m);
            });
            out.push((
                CAVEAT_DAILY_TOTALS,
                payload.finish().map_err(CapabilityError::Encode)?,
            ));
        }
        if let Some(root) = self.daily_root {
            out.push((CAVEAT_DAILY_ROOT, root.to_vec()));
        }
        if self.profile == Profile::Human && self.operator_kind == OperatorKind::Agent {
            out.push((CAVEAT_OPERATOR_KIND, vec![OperatorKind::Agent.tag()]));
        }
        if self.requires_dry_run && self.profile != Profile::Agent {
            out.push((CAVEAT_REQUIRES_DRY_RUN, vec![1u8]));
        }
        if let Some(classes) = &self.classes {
            let tags: Vec<u16> = classes.iter().map(|c| c.0).collect();
            let mut payload = Writer::with_capacity(4 + tags.len() * 2);
            payload.list(&tags, |w, t| {
                w.u16(*t);
            });
            out.push((
                CAVEAT_CLASSES,
                payload.finish().map_err(CapabilityError::Encode)?,
            ));
        }
        Ok(out)
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
        let mut redaction = None;
        let mut accounts = None;
        let mut periods = None;
        let mut effective_through = None;
        let mut known_at = None;
        let mut branch = None;
        let mut possession = None;
        let mut daily_totals = Vec::new();
        let mut daily_root = None;
        let mut operator_kind = None;
        let mut requires_dry_run = false;
        let mut classes = None;
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
                    CAVEAT_REDACTION => {
                        let mut p = Reader::new(payload);
                        let id = p
                            .u16("capability.redaction")
                            .map_err(CapabilityError::Decode)?;
                        p.finish().map_err(CapabilityError::Decode)?;
                        redaction = Some(id);
                    }
                    CAVEAT_ACCOUNTS => {
                        accounts = Some(decode_codes(
                            payload,
                            MAX_ACCOUNT_ROOTS,
                            MAX_ACCOUNT_CODE_BYTES,
                            "capability.accounts",
                            CapabilityError::BadAccounts,
                        )?);
                    }
                    CAVEAT_PERIODS => {
                        periods = Some(decode_codes(
                            payload,
                            MAX_PERIODS,
                            MAX_PERIOD_CODE_BYTES,
                            "capability.periods",
                            CapabilityError::BadPeriods,
                        )?);
                    }
                    CAVEAT_EFFECTIVE => {
                        let mut p = Reader::new(payload);
                        let day = p
                            .i32("capability.effective")
                            .map_err(CapabilityError::Decode)?;
                        p.finish().map_err(CapabilityError::Decode)?;
                        effective_through = Some(DateDay(day));
                    }
                    CAVEAT_KNOWN_AT => {
                        let mut p = Reader::new(payload);
                        let seq = p
                            .u64("capability.known_at")
                            .map_err(CapabilityError::Decode)?;
                        p.finish().map_err(CapabilityError::Decode)?;
                        known_at = Some(CommitSeq(seq));
                    }
                    CAVEAT_BRANCH => {
                        let mut p = Reader::new(payload);
                        let id = p
                            .fixed("capability.branch")
                            .map_err(CapabilityError::Decode)?;
                        p.finish().map_err(CapabilityError::Decode)?;
                        branch = Some(Id128(id));
                    }
                    CAVEAT_POSSESSION => {
                        let mut p = Reader::new(payload);
                        let digest = p
                            .fixed("capability.possession")
                            .map_err(CapabilityError::Decode)?;
                        p.finish().map_err(CapabilityError::Decode)?;
                        possession = Some(digest);
                    }
                    CAVEAT_DAILY_TOTALS => {
                        daily_totals = decode_daily_totals(payload)?;
                    }
                    CAVEAT_DAILY_ROOT => {
                        let mut p = Reader::new(payload);
                        let root = p
                            .fixed("capability.daily_root")
                            .map_err(CapabilityError::Decode)?;
                        p.finish().map_err(CapabilityError::Decode)?;
                        daily_root = Some(root);
                    }
                    CAVEAT_OPERATOR_KIND => {
                        if profile != Profile::Human
                            || payload.as_slice() != [OperatorKind::Agent.tag()]
                        {
                            return Err(CapabilityError::BadOperatorKind);
                        }
                        operator_kind = Some(OperatorKind::Agent);
                    }
                    CAVEAT_REQUIRES_DRY_RUN => {
                        if profile == Profile::Agent || payload.as_slice() != [1u8] {
                            return Err(CapabilityError::BadRequiresDryRun);
                        }
                        requires_dry_run = true;
                    }
                    CAVEAT_CLASSES => {
                        classes = Some(decode_classes(payload)?);
                    }
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
        if let Some(contract) = redaction {
            cap = cap.with_redaction(contract)?;
        }
        if let Some(codes) = accounts {
            let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
            cap = cap.for_accounts(&codes)?;
        }
        if let Some(codes) = periods {
            let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
            cap = cap.for_periods(&codes)?;
        }
        if let Some(day) = effective_through {
            cap = cap.effective_through(day);
        }
        if let Some(seq) = known_at {
            cap = cap.known_at_most(seq);
        }
        if let Some(branch) = branch {
            cap = cap.on_branch(branch)?;
        }
        if let Some(digest) = possession {
            cap = cap.holder_bound(digest);
        }
        for (unit, max) in daily_totals {
            cap = cap.with_daily_total(unit, max)?;
        }
        if let Some(root) = daily_root {
            cap = cap.with_daily_root(root)?;
        }
        if let Some(kind) = operator_kind {
            cap = cap.with_operator_kind(kind)?;
        }
        if requires_dry_run {
            cap = cap.with_requires_dry_run();
        }
        if let Some(classes) = classes {
            cap = cap.for_classes(&classes)?;
        }
        Ok(cap)
    }
}

fn decode_classes(payload: &[u8]) -> Result<Vec<EntryClass>, CapabilityError> {
    let mut r = Reader::new(payload);
    let raw = r
        .list(MAX_CLASSES, "capability.classes", |r| {
            r.u16("capability.class")
        })
        .map_err(CapabilityError::Decode)?;
    if raw.is_empty() {
        return Err(CapabilityError::BadClasses);
    }
    if !raw.windows(2).all(|w| w[0] < w[1]) {
        return Err(CapabilityError::Decode(r.unsorted("capability.classes")));
    }
    r.finish().map_err(CapabilityError::Decode)?;
    let mut out = Vec::with_capacity(raw.len());
    for tag in raw {
        let class = EntryClass(tag);
        if class.name().is_none() {
            return Err(CapabilityError::BadClasses);
        }
        out.push(class);
    }
    Ok(out)
}

/// The daily-total payload is non-empty, bounded, strictly ascending by
/// unit and exact in length. The constructor checks each positive bound.
fn decode_daily_totals(payload: &[u8]) -> Result<Vec<(UnitId, i128)>, CapabilityError> {
    let mut r = Reader::new(payload);
    let totals = r
        .list(MAX_DAILY_TOTALS, "capability.daily_totals", |r| {
            Ok((
                UnitId(r.u32("daily_total.unit")?),
                r.i128("daily_total.max")?,
            ))
        })
        .map_err(CapabilityError::Decode)?;
    if totals.is_empty() {
        return Err(CapabilityError::Decode(
            r.invalid("capability.daily_totals"),
        ));
    }
    if !totals.windows(2).all(|w| w[0].0 < w[1].0) {
        return Err(CapabilityError::Decode(
            r.unsorted("capability.daily_totals"),
        ));
    }
    r.finish().map_err(CapabilityError::Decode)?;
    Ok(totals)
}

/// `codes` as a set when it names 1..=`max` codes of 1..=`max_bytes` bytes.
fn bounded_codes(codes: &[&str], max: usize, max_bytes: usize) -> Option<BTreeSet<String>> {
    if codes.is_empty()
        || codes.len() > max
        || codes.iter().any(|c| c.is_empty() || c.len() > max_bytes)
    {
        return None;
    }
    Some(codes.iter().map(|c| (*c).to_string()).collect())
}

/// A conjunctive narrowing: what is held intersected with what is named,
/// or `None` when nothing remains.
fn narrow<T: Ord + Clone>(held: Option<BTreeSet<T>>, named: BTreeSet<T>) -> Option<BTreeSet<T>> {
    let next: BTreeSet<T> = match held {
        Some(held) => held.intersection(&named).cloned().collect(),
        None => named,
    };
    (!next.is_empty()).then_some(next)
}

/// The `accounts`/`periods` payload: `list(str code, ascending)`.
fn encode_codes(codes: &BTreeSet<String>) -> Result<Vec<u8>, CapabilityError> {
    let codes: Vec<&String> = codes.iter().collect();
    let mut payload = Writer::with_capacity(4 + codes.iter().map(|c| 4 + c.len()).sum::<usize>());
    payload.list(&codes, |w, c| {
        w.str(c);
    });
    payload.finish().map_err(CapabilityError::Encode)
}

/// Decode `list(str code, ascending)`: non-empty, bounded, strictly
/// ascending, no trailing bytes; `bad` names the caveat's shape error.
fn decode_codes(
    payload: &[u8],
    max: usize,
    max_bytes: usize,
    what: &'static str,
    bad: CapabilityError,
) -> Result<Vec<String>, CapabilityError> {
    let mut r = Reader::new(payload);
    let codes = r
        .list(max, what, |r| r.str(max_bytes, what).map(str::to_string))
        .map_err(CapabilityError::Decode)?;
    if codes.is_empty() || codes.iter().any(String::is_empty) {
        return Err(bad);
    }
    if !codes.windows(2).all(|w| w[0] < w[1]) {
        return Err(CapabilityError::Decode(r.unsorted(what)));
    }
    r.finish().map_err(CapabilityError::Decode)?;
    Ok(codes)
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

const TOKEN_MAGIC: &[u8; 13] = b"FA-CAP-TOKEN\0";
const TOKEN_VERSION: u16 = 1;
/// Bytes a principal name may take in a token (the launch bound).
pub const MAX_TOKEN_PRINCIPAL_BYTES: usize = 256;
/// The bound on a whole token file.
pub const MAX_TOKEN_BYTES: usize = 64 * 1024;

/// What an issued capability's holder keeps (plan §14.2, bead fa-v62): the
/// principal's name, the holder-bound capability exactly as journaled, and
/// the secret whose [`possession_digest`] the capability carries. It is
/// written 0600 and never journaled. Only the issuance makes it usable: the
/// kernel admits the capability against its journaled issuance.
#[derive(Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    principal: String,
    capability: Capability,
    secret: [u8; 32],
}

impl fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapabilityToken")
            .field("principal", &self.principal)
            .field("capability", &self.capability)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl CapabilityToken {
    /// A token whose secret proves the capability's possession digest and
    /// whose principal derives the capability's holder.
    pub fn new(
        principal: impl Into<String>,
        capability: Capability,
        secret: [u8; 32],
    ) -> Result<Self, CapabilityError> {
        let principal = principal.into();
        if principal.is_empty() || principal.len() > MAX_TOKEN_PRINCIPAL_BYTES {
            return Err(CapabilityError::BadToken(
                "the principal name is 1..=256 bytes",
            ));
        }
        if fa_model::principal_vid(&principal) != capability.holder() {
            return Err(CapabilityError::BadToken(
                "the principal does not hold this capability",
            ));
        }
        if !capability.proves_possession(&secret) {
            return Err(CapabilityError::BadToken(
                "the secret does not prove the capability's possession digest",
            ));
        }
        Ok(Self {
            principal,
            capability,
            secret,
        })
    }

    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    #[must_use]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// `magic ‖ u16 version ‖ str principal ‖ bytes capability ‖ secret[32]`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CapabilityError> {
        let mut w = Writer::with_capacity(512);
        w.fixed(TOKEN_MAGIC)
            .u16(TOKEN_VERSION)
            .str(&self.principal)
            .bytes(&self.capability.canonical_bytes()?)
            .fixed(&self.secret);
        w.finish().map_err(CapabilityError::Encode)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CapabilityError> {
        if bytes.len() > MAX_TOKEN_BYTES {
            return Err(CapabilityError::BadToken("the token exceeds its bound"));
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<13>("token.magic")
            .map_err(CapabilityError::Decode)?
            != *TOKEN_MAGIC
        {
            return Err(CapabilityError::BadToken("not a capability token"));
        }
        if r.u16("token.version").map_err(CapabilityError::Decode)? != TOKEN_VERSION {
            return Err(CapabilityError::BadToken("unsupported token version"));
        }
        let principal = r
            .str(MAX_TOKEN_PRINCIPAL_BYTES, "token.principal")
            .map_err(CapabilityError::Decode)?
            .to_string();
        let capability = Capability::decode(
            r.bytes(MAX_TOKEN_BYTES, "token.capability")
                .map_err(CapabilityError::Decode)?,
        )?;
        let secret = r.fixed("token.secret").map_err(CapabilityError::Decode)?;
        r.finish().map_err(CapabilityError::Decode)?;
        Self::new(principal, capability, secret)
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

    /// fa-v62: the possession caveat binds a holder secret into the
    /// commitment, round-trips, leaves the token unscoped, and only the
    /// secret itself proves possession.
    #[test]
    fn a_holder_bound_capability_commits_to_its_secret_and_only_that_secret_proves_it() {
        let secret = [5; 32];
        let bound = agent().holder_bound(possession_digest(&secret));
        let bytes = bound.canonical_bytes().unwrap();
        assert_eq!(Capability::decode(&bytes).unwrap(), bound);
        assert_eq!(bound.possession(), Some(possession_digest(&secret)));
        assert!(bound.proves_possession(&secret));
        assert!(!bound.proves_possession(&[6; 32]));
        assert!(
            !agent().proves_possession(&secret),
            "an unbound token proves nothing"
        );
        assert!(!bound.is_scoped(), "possession is not a scope caveat");
        // The binding is part of the commitment: another secret, or no
        // binding at all, is another capability.
        let c = bound.commitment().unwrap();
        assert_ne!(agent().commitment().unwrap(), c);
        assert_ne!(
            agent()
                .holder_bound(possession_digest(&[6; 32]))
                .commitment()
                .unwrap(),
            c
        );
        // A truncated possession payload does not decode.
        let short = Capability::decode(&bytes[..bytes.len() - 1]);
        assert!(short.is_err());
    }

    /// fa-v62: a token round-trips; it holds only when its secret proves the
    /// possession digest and its principal derives the holder.
    #[test]
    fn a_capability_token_round_trips_and_holds_only_with_its_secret_and_holder() {
        let secret = [3; 32];
        let holder = fa_model::principal_vid("agent-7");
        let cap = Capability::new(holder, Profile::Agent, &[Op::Read, Op::Post], VId(1))
            .unwrap()
            .holder_bound(possession_digest(&secret));
        let token = CapabilityToken::new("agent-7", cap.clone(), secret).unwrap();
        let bytes = token.canonical_bytes().unwrap();
        assert_eq!(CapabilityToken::decode(&bytes).unwrap(), token);
        assert!(
            !format!("{token:?}").contains("[3, 3"),
            "the secret is never printed"
        );
        assert!(CapabilityToken::new("agent-7", cap.clone(), [4; 32]).is_err());
        assert!(CapabilityToken::new("agent-8", cap.clone(), secret).is_err());
        assert!(CapabilityToken::new("agent-7", agent(), secret).is_err());
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            CapabilityToken::decode(&tampered).is_err(),
            "a wrong secret"
        );
        assert!(CapabilityToken::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(CapabilityToken::decode(&trailing).is_err());
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
        // Two caveats: books (tag 1), then redaction = 1 (tag 2, fa-kuu).
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
            "02",                               //   tag 2, redaction
            "02000000",                         //   2 payload bytes:
            "0100",                             //     contract 1
        ));
        let redacted = scoped.clone().with_redaction(1).unwrap();
        assert_eq!(redacted.canonical_bytes().unwrap(), v2_two);
        assert_eq!(Capability::decode(&v2_two).unwrap(), redacted);
        assert_eq!(redacted.redaction(), Some(1));
        assert!(!redacted.is_scoped());
        // An unknown caveat tag fails closed rather than decoding as
        // less restricted than it was issued.
        let v2_unknown = hex(concat!(
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
            "ff",                               //   tag 255 (unknown)
            "00000000",                         //   empty payload
        ));
        assert_eq!(
            Capability::decode(&v2_unknown),
            Err(CapabilityError::UnknownCaveat { tag: 255 })
        );
        // Tags are strictly ascending, and a v2 names at least one caveat.
        let mut swapped = v2.clone();
        swapped.truncate(v2.len() - 29); // drop the caveat list
        swapped.extend_from_slice(&hex(concat!(
            "02000000",
            "02",
            "02000000",
            "0100",
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
    fn redaction_caveat_validates_registered_contract_and_cannot_be_dropped_or_moved() {
        let priv_cap = Capability::embedded(VId(1), &["read", "privileged"]).unwrap();
        assert_eq!(priv_cap.redaction(), None);
        assert!(priv_cap.reveals_contract(1));

        // Adding contract 1 confines the capability even when it holds `privileged`.
        let caveated = priv_cap.clone().with_redaction(1).unwrap();
        assert_eq!(caveated.redaction(), Some(1));
        assert!(!caveated.reveals_contract(1));
        assert!(caveated.reveals_contract(2));
        assert_ne!(
            caveated.commitment().unwrap(),
            priv_cap.commitment().unwrap()
        );

        // Repeating the same contract is a no-op.
        assert_eq!(caveated.clone().with_redaction(1).unwrap(), caveated);

        // Unregistered contract ids (0, 99) are refused at construction and decode.
        for bad in [0u16, 99u16] {
            assert_eq!(
                priv_cap.clone().with_redaction(bad),
                Err(CapabilityError::BadRedaction { contract: bad })
            );
            let mut raw = priv_cap.canonical_bytes().unwrap();
            raw[..2].copy_from_slice(&2u16.to_le_bytes());
            raw.extend_from_slice(&1u32.to_le_bytes()); // one caveat
            raw.push(CAVEAT_REDACTION);
            raw.extend_from_slice(&2u32.to_le_bytes()); // 2-byte payload
            raw.extend_from_slice(&bad.to_le_bytes());
            assert_eq!(
                Capability::decode(&raw),
                Err(CapabilityError::BadRedaction { contract: bad })
            );
        }
        // Empty or trailing payload for tag 2 does not decode.
        for bad_payload in [&[][..], &[1, 0, 0][..]] {
            let mut raw = priv_cap.canonical_bytes().unwrap();
            raw[..2].copy_from_slice(&2u16.to_le_bytes());
            raw.extend_from_slice(&1u32.to_le_bytes());
            raw.push(CAVEAT_REDACTION);
            raw.extend_from_slice(&u32::try_from(bad_payload.len()).unwrap().to_le_bytes());
            raw.extend_from_slice(bad_payload);
            assert!(matches!(
                Capability::decode(&raw),
                Err(CapabilityError::Decode(_))
            ));
        }
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

    /// The new caveats append after possession without changing its tag or
    /// the base encoding. Daily limits and the shared root each bind the
    /// commitment, including when they coexist with a holder-bound token.
    #[test]
    fn daily_total_and_root_bytes_are_golden_after_possession() {
        let golden = hex(concat!(
            "0200",                             // version 2
            "01000000000000000000000000000000", // holder VId(1)
            "00",                               // profile Human
            "01000000",                         // one op:
            "06",                               //   close
            "00000000",                         // no per-leg ceilings
            "00",                               // no expiry
            "01000000000000000000000000000000", // issuer VId(1)
            "03000000",                         // three caveats:
            "08",                               //   possession
            "20000000",                         //   32 payload bytes:
            "0404040404040404040404040404040404040404040404040404040404040404",
            "09",       //   daily totals
            "2c000000", //   44 payload bytes:
            "02000000", //     two units,
            "02000000", //     UnitId(2), max 1000,
            "e8030000000000000000000000000000",
            "09000000", //     UnitId(9), max 2000
            "d0070000000000000000000000000000",
            "0a",       //   daily root
            "20000000", //   32 payload bytes:
            "0303030303030303030303030303030303030303030303030303030303030303",
        ));
        let root = Capability::embedded(VId(1), &["close"])
            .unwrap()
            .holder_bound([4; 32])
            .with_daily_total(UnitId(9), 2_000)
            .unwrap()
            .with_daily_total(UnitId(2), 1_000)
            .unwrap();
        assert_eq!(root.daily_root(), None);
        let child = root.clone().with_daily_root([3; 32]).unwrap();
        assert_eq!(child.canonical_bytes().unwrap(), golden);
        assert_eq!(Capability::decode(&golden).unwrap(), child);
        assert!(!child.is_scoped(), "daily quotas do not alter read reach");
        assert_ne!(root.commitment().unwrap(), child.commitment().unwrap());
        assert_ne!(
            root.with_daily_root([5; 32]).unwrap().commitment().unwrap(),
            child.commitment().unwrap()
        );
        assert_ne!(
            child
                .clone()
                .with_daily_total(UnitId(2), 999)
                .unwrap()
                .commitment()
                .unwrap(),
            child.commitment().unwrap()
        );
    }

    #[test]
    fn daily_total_narrowing_preserves_the_root_and_independent_per_leg_limits() {
        let cap = agent()
            .with_daily_total(UnitId(0), 400_000)
            .unwrap()
            .with_daily_total(UnitId(1), 200_000)
            .unwrap()
            .with_daily_root([7; 32])
            .unwrap();
        for proposed in [1, 399_999, 400_000, 400_001, i128::MAX] {
            let narrowed = cap.clone().with_daily_total(UnitId(0), proposed).unwrap();
            assert_eq!(
                narrowed.daily_totals().get(&UnitId(0)),
                Some(&proposed.min(400_000))
            );
            assert_eq!(narrowed.daily_totals().get(&UnitId(1)), Some(&200_000));
            assert_eq!(narrowed.daily_root(), Some([7; 32]));
            assert_eq!(narrowed.ceilings(), cap.ceilings());
            assert_eq!(narrowed.clone().with_daily_root([7; 32]).unwrap(), narrowed);
            assert_eq!(
                narrowed.with_daily_root([8; 32]),
                Err(CapabilityError::BadDailyRoot)
            );
        }
        assert_eq!(
            agent().with_daily_root([7; 32]),
            Err(CapabilityError::BadDailyRoot),
            "a root cannot exist without daily limits"
        );
        for max_mantissa in [0, -1, i128::MIN] {
            assert_eq!(
                cap.clone().with_daily_total(UnitId(0), max_mantissa),
                Err(CapabilityError::BadDailyTotal {
                    unit: UnitId(0),
                    max_mantissa
                })
            );
        }
        let mut maximum = agent();
        for unit in 0..u32::try_from(MAX_DAILY_TOTALS).unwrap() {
            maximum = maximum.with_daily_total(UnitId(unit), i128::MAX).unwrap();
        }
        assert_eq!(
            Capability::decode(&maximum.canonical_bytes().unwrap()).unwrap(),
            maximum
        );
        assert_eq!(
            maximum.with_daily_total(UnitId(u32::MAX), 1),
            Err(CapabilityError::TooManyDailyTotals)
        );
    }

    #[test]
    fn daily_total_decoding_refuses_malformed_maps_roots_and_tags() {
        fn caveated(caveats: &[(u8, Vec<u8>)]) -> Vec<u8> {
            let mut bytes = Capability::embedded(VId(1), &["post"])
                .unwrap()
                .canonical_bytes()
                .unwrap();
            bytes[..2].copy_from_slice(&CAPABILITY_VERSION_CAVEATS.to_le_bytes());
            let mut w = Writer::with_capacity(256);
            w.list(caveats, |w, (tag, payload)| {
                w.u8(*tag).bytes(payload);
            });
            bytes.extend_from_slice(&w.finish().unwrap());
            bytes
        }
        fn totals(values: &[(u32, i128)]) -> Vec<u8> {
            let mut w = Writer::with_capacity(64);
            w.list(values, |w, (unit, max)| {
                w.u32(*unit).i128(*max);
            });
            w.finish().unwrap()
        }
        let valid = totals(&[(2, 1_000)]);
        let mut trailing = valid.clone();
        trailing.push(0);
        let oversized = u32::try_from(MAX_DAILY_TOTALS + 1)
            .unwrap()
            .to_le_bytes()
            .to_vec();
        for payload in [
            totals(&[]),
            totals(&[(2, 1_000), (1, 1_000)]),
            totals(&[(2, 1_000), (2, 900)]),
            totals(&[(2, 0)]),
            totals(&[(2, -1)]),
            oversized,
            valid[..valid.len() - 1].to_vec(),
            trailing,
        ] {
            assert!(
                Capability::decode(&caveated(&[(CAVEAT_DAILY_TOTALS, payload)])).is_err(),
                "a noncanonical daily-total map must not decode"
            );
        }
        assert_eq!(
            Capability::decode(&caveated(&[(CAVEAT_DAILY_ROOT, vec![7; 32])])),
            Err(CapabilityError::BadDailyRoot)
        );
        for root in [vec![7; 31], vec![7; 33]] {
            assert!(
                Capability::decode(&caveated(&[
                    (CAVEAT_DAILY_TOTALS, valid.clone()),
                    (CAVEAT_DAILY_ROOT, root),
                ]))
                .is_err()
            );
        }
        for caveats in [
            vec![
                (CAVEAT_DAILY_TOTALS, valid.clone()),
                (CAVEAT_DAILY_TOTALS, valid.clone()),
            ],
            vec![
                (CAVEAT_DAILY_ROOT, vec![7; 32]),
                (CAVEAT_DAILY_TOTALS, valid.clone()),
            ],
        ] {
            assert!(Capability::decode(&caveated(&caveats)).is_err());
        }
        assert_eq!(
            Capability::decode(&caveated(&[(14, Vec::new())])),
            Err(CapabilityError::UnknownCaveat { tag: 14 })
        );
    }

    #[test]
    fn holder_bound_token_round_trip_preserves_daily_limits_and_shared_root() {
        let secret = [3; 32];
        let cap = Capability::new(
            fa_model::principal_vid("daily-holder"),
            Profile::Human,
            &[Op::Read, Op::Post],
            VId(1),
        )
        .unwrap()
        .holder_bound(possession_digest(&secret))
        .with_daily_total(UnitId(0), 5_000)
        .unwrap()
        .with_daily_root([8; 32])
        .unwrap();
        let token = CapabilityToken::new("daily-holder", cap, secret).unwrap();
        let bytes = token.canonical_bytes().unwrap();
        assert_eq!(CapabilityToken::decode(&bytes).unwrap(), token);
        assert_eq!(
            token.capability().daily_totals().get(&UnitId(0)),
            Some(&5_000)
        );
        assert_eq!(token.capability().daily_root(), Some([8; 32]));
        assert!(token.capability().proves_possession(&secret));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn scoped() -> Capability {
        Capability::embedded(VId(1), &["close"])
            .unwrap()
            .for_accounts(&["6100"])
            .unwrap()
            .for_periods(&["FY2026-P03"])
            .unwrap()
            .effective_through(DateDay(20_000))
            .known_at_most(CommitSeq(9))
            .on_branch(Id128([3; 16]))
            .unwrap()
    }

    /// Golden bytes for the scope caveats (tags 3–7), written from the
    /// documented layout: each is an additive v2 tag after `books`' slot,
    /// and tag 2 (`redaction`, fa-kuu) stays unknown.
    #[test]
    fn scope_caveat_bytes_are_golden() {
        let golden = hex(concat!(
            "0200",                             // version 2
            "01000000000000000000000000000000", // holder VId(1)
            "00",                               // profile Human
            "01000000",                         // one op:
            "06",                               //   close
            "00000000",                         // no ceilings
            "00",                               // no expiry
            "01000000000000000000000000000000", // issuer VId(1)
            "05000000",                         // five caveats:
            "03",                               //   tag 3, accounts
            "0c000000",                         //   12 payload bytes:
            "01000000",                         //     one root,
            "04000000",                         //     4 bytes
            "36313030",                         //     "6100"
            "04",                               //   tag 4, periods
            "12000000",                         //   18 payload bytes:
            "01000000",                         //     one period,
            "0a000000",                         //     10 bytes
            "4659323032362d503033",             //     "FY2026-P03"
            "05",                               //   tag 5, effective
            "04000000",                         //   4 payload bytes:
            "204e0000",                         //     day 20000
            "06",                               //   tag 6, known_at
            "08000000",                         //   8 payload bytes:
            "0900000000000000",                 //     seq 9
            "07",                               //   tag 7, branch
            "10000000",                         //   16 payload bytes:
            "03030303030303030303030303030303", //     Id128([3; 16])
        ));
        let cap = scoped();
        assert_eq!(cap.canonical_bytes().unwrap(), golden);
        let decoded = Capability::decode(&golden).unwrap();
        assert_eq!(decoded, cap);
        assert!(decoded.is_scoped());
        assert_eq!(decoded.effective_bound(), Some(DateDay(20_000)));
        assert_eq!(decoded.known_at_pin(), Some(CommitSeq(9)));
        assert_eq!(decoded.branch(), Some(Id128([3; 16])));
        assert!(decoded.accounts().unwrap().contains("6100"));
        assert!(decoded.periods().unwrap().contains("FY2026-P03"));
        // Each scope caveat is bound by the commitment.
        let c = cap.commitment().unwrap();
        let plain = Capability::embedded(VId(1), &["close"]).unwrap();
        assert!(!plain.is_scoped());
        for other in [
            plain.clone().for_accounts(&["6100"]).unwrap(),
            plain.clone().for_periods(&["FY2026-P03"]).unwrap(),
            plain.clone().effective_through(DateDay(20_000)),
            plain.clone().known_at_most(CommitSeq(9)),
            plain.clone().on_branch(Id128([3; 16])).unwrap(),
            scoped().effective_through(DateDay(19_999)),
            scoped().known_at_most(CommitSeq(8)),
        ] {
            assert!(other.is_scoped());
            assert_ne!(other.commitment().unwrap(), c, "{other:?}");
        }
        // A trailing byte inside a payload, or an empty code list, is refused.
        let mut long_effective = golden.clone();
        let at = golden.len() - (1 + 4 + 16) - (1 + 4 + 8) - 4; // the day
        long_effective[at - 4] = 5; // payload length 5 …
        long_effective.insert(at + 4, 0); // … with one extra byte
        assert!(matches!(
            Capability::decode(&long_effective),
            Err(CapabilityError::Decode(_))
        ));
    }

    #[test]
    fn scope_caveats_only_narrow_and_an_empty_scope_is_refused() {
        let cap = Capability::embedded(VId(1), &["post"])
            .unwrap()
            .for_accounts(&["6100", "1000"])
            .unwrap()
            .for_periods(&["FY2026-P03", "FY2026-P04"])
            .unwrap();
        // Accounts and periods intersect; a root not held is not added.
        let narrowed = cap
            .clone()
            .for_accounts(&["6100", "2000"])
            .unwrap()
            .for_periods(&["FY2026-P04"])
            .unwrap();
        assert_eq!(
            narrowed.accounts().unwrap().iter().collect::<Vec<_>>(),
            ["6100"]
        );
        assert_eq!(
            narrowed.periods().unwrap().iter().collect::<Vec<_>>(),
            ["FY2026-P04"]
        );
        assert_eq!(
            cap.clone().for_accounts(&["6110"]),
            Err(CapabilityError::BadAccounts),
            "a descendant root is a fresh issuance, not an attenuation"
        );
        assert_eq!(
            cap.clone().for_periods(&["FY2026-P05"]),
            Err(CapabilityError::BadPeriods)
        );
        // Codes are bounded and non-empty.
        let base = Capability::embedded(VId(1), &["post"]).unwrap();
        assert_eq!(
            base.clone().for_accounts(&[]),
            Err(CapabilityError::BadAccounts)
        );
        assert_eq!(
            base.clone().for_accounts(&[""]),
            Err(CapabilityError::BadAccounts)
        );
        let long = "x".repeat(MAX_ACCOUNT_CODE_BYTES + 1);
        assert_eq!(
            base.clone().for_accounts(&[long.as_str()]),
            Err(CapabilityError::BadAccounts)
        );
        assert_eq!(
            base.clone().for_periods(&[]),
            Err(CapabilityError::BadPeriods)
        );
        // Dates and pins only tighten; a branch never moves.
        let bounded = base
            .clone()
            .effective_through(DateDay(10))
            .effective_through(DateDay(20))
            .known_at_most(CommitSeq(5))
            .known_at_most(CommitSeq(7));
        assert_eq!(bounded.effective_bound(), Some(DateDay(10)));
        assert_eq!(bounded.known_at_pin(), Some(CommitSeq(5)));
        let drafted = base.on_branch(Id128([4; 16])).unwrap();
        assert_eq!(
            drafted.clone().on_branch(Id128([4; 16])).unwrap().branch(),
            Some(Id128([4; 16]))
        );
        assert_eq!(
            drafted.on_branch(Id128::TRUNK),
            Err(CapabilityError::BadBranch)
        );
    }

    #[test]
    fn a_code_caveat_that_names_nothing_or_is_unsorted_does_not_decode() {
        let plain = Capability::embedded(VId(3), &["post"]).unwrap();
        let caveat = |tag: u8, payload: &[u8]| {
            let mut bytes = plain.canonical_bytes().unwrap();
            bytes[..2].copy_from_slice(&2u16.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes()); // one caveat
            bytes.push(tag);
            bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(payload);
            bytes
        };
        // Zero codes.
        assert_eq!(
            Capability::decode(&caveat(CAVEAT_ACCOUNTS, &0u32.to_le_bytes())),
            Err(CapabilityError::BadAccounts)
        );
        assert_eq!(
            Capability::decode(&caveat(CAVEAT_PERIODS, &0u32.to_le_bytes())),
            Err(CapabilityError::BadPeriods)
        );
        // Two codes out of order.
        let unsorted = hex(concat!("02000000", "01000000", "62", "01000000", "61"));
        assert!(matches!(
            Capability::decode(&caveat(CAVEAT_PERIODS, &unsorted)),
            Err(CapabilityError::Decode(_))
        ));
        // A sorted pair decodes.
        let sorted = hex(concat!("02000000", "01000000", "61", "01000000", "62"));
        let two = Capability::decode(&caveat(CAVEAT_ACCOUNTS, &sorted)).unwrap();
        assert_eq!(two.accounts().unwrap().len(), 2);
        // A truncated pin.
        assert!(matches!(
            Capability::decode(&caveat(CAVEAT_KNOWN_AT, &[1, 0, 0])),
            Err(CapabilityError::Decode(_))
        ));
    }
}
