//! Typed refusals and kernel failures, mapped to the exit-code contract
//! (plan §15.3, `registries/exit_codes.toml`).
//!
//! A [`Refusal`] is the lawful "no": the book is unchanged, and the value
//! carries the code the catalog will list, the exit class, what failed, the
//! law or cell cited, and the exact fix. A [`KernelError`] is a foundation
//! failure (exit 5): the substrate or a codec failed and the caller must not
//! pretend otherwise.

use core::fmt;

/// Exit classes, as `registries/exit_codes.toml` registers them. The
/// `exit_classes_match_registry` test keeps these equal to the registry.
pub mod exit {
    pub const SUCCESS: u8 = 0;
    pub const USAGE: u8 = 2;
    pub const REFUSAL: u8 = 3;
    pub const ENVIRONMENT: u8 = 4;
    pub const FOUNDATION: u8 = 5;
    pub const CONFLICT: u8 = 6;
    pub const SAFETY: u8 = 7;
    pub const VERIFICATION: u8 = 8;
}

/// A lawful refusal. The book is unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// Stable catalog code, `FA-REF-nnn`.
    pub code: &'static str,
    /// The exit class (`exit::*`).
    pub exit: u8,
    /// What failed, in one sentence.
    pub message: String,
    /// The law, invariant, matrix cell, or policy row cited.
    pub cite: String,
    /// The exact next step, copy-pasteable where possible.
    pub fix: String,
}

impl Refusal {
    pub fn new(
        code: &'static str,
        exit: u8,
        message: impl Into<String>,
        cite: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            code,
            exit,
            message: message.into(),
            cite: cite.into(),
            fix: fix.into(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (exit {}): {} [{}] fix: {}",
            self.code, self.exit, self.message, self.cite, self.fix
        )
    }
}

/// Refusal codes this crate emits. The catalog (`refusal_catalog.toml`) is a
/// later bead; until it lands these constants are the registry.
pub mod code {
    /// Balance law: debits ≠ credits in some unit.
    pub const UNBALANCED: &str = "FA-REF-001";
    /// A leg posts to a summary (non-leaf) account.
    pub const NOT_A_LEAF: &str = "FA-REF-002";
    /// A leg's unit violates the account's unit policy.
    pub const UNIT_POLICY: &str = "FA-REF-003";
    /// A leg names an account the book does not have.
    pub const UNKNOWN_ACCOUNT: &str = "FA-REF-004";
    /// The class × period-state cell is `refuse`.
    pub const PERIOD_LAW: &str = "FA-REF-010";
    /// The cell requires a capability op the principal lacks.
    pub const CAPABILITY: &str = "FA-REF-011";
    /// The cell requires more approvals than the transcript carries.
    pub const APPROVALS: &str = "FA-REF-012";
    /// The effective date resolves to no period or needs a discriminator.
    pub const PERIOD_RESOLVE: &str = "FA-REF-020";
    /// The period is not part of the book (never created).
    pub const PERIOD_UNKNOWN: &str = "FA-REF-021";
    /// First-committer-wins: a concurrent commit invalidated a witness.
    pub const CONFLICT: &str = "FA-REF-030";
    /// The period moved under the transition (compare-and-set mismatch).
    pub const PERIOD_MOVED: &str = "FA-REF-031";
    /// The requested period transition is not a legal edge of the state machine.
    pub const TRANSITION: &str = "FA-REF-040";
    /// The payload violates the schema's structural rules.
    pub const STRUCTURE: &str = "FA-REF-100";
    /// A control class was sent through `post`.
    pub const CONTROL_VIA_POST: &str = "FA-REF-101";
    /// The class is registered but its semantics are not enforced by this slice.
    pub const CLASS_NOT_IMPLEMENTED: &str = "FA-REF-102";
    /// The proposal names a different book, or a branch, than the one being written.
    pub const COORDINATE: &str = "FA-REF-103";
    /// The idempotency key was reused with different content.
    pub const IDEMPOTENCY_CONFLICT: &str = "FA-REF-032";
    /// A Reversal names no target, a target that does not exist, or a digest that does not match.
    pub const REVERSAL_TARGET: &str = "FA-REF-050";
    /// A Reversal's legs are not the exact side-swap of the target's legs.
    pub const REVERSAL_SHAPE: &str = "FA-REF-051";
    /// The target is already reversed by another entry.
    pub const ALREADY_REVERSED: &str = "FA-REF-052";
    /// The named pending entry is missing, is not a `Pending`, or its handle digest mismatches.
    pub const RESOLUTION_TARGET: &str = "FA-REF-060";
    /// The posted sub-vector is not drawn leg-by-leg from the pending entry.
    pub const RESOLUTION_SHAPE: &str = "FA-REF-061";
    /// The pending entry already has its one resolution.
    pub const ALREADY_RESOLVED: &str = "FA-REF-062";
    /// The settlement names an entry that is missing, not posted, reversed, or whose handle digest mismatches.
    pub const SETTLE_TARGET: &str = "FA-REF-070";
    /// The settlement does not fit its legs: wrong ordinal, account, unit, or side; sum over the leg; a Reversal applying.
    pub const SETTLE_SHAPE: &str = "FA-REF-071";
    /// The settlement exceeds the target leg's open amount.
    pub const OVER_APPLICATION: &str = "FA-REF-072";
    /// The reversal target has live applications against its legs.
    pub const LIVE_APPLICATIONS: &str = "FA-REF-073";
    /// A key collided but equivalence cannot be verified: a sealed field is erased or under a key this book lacks.
    pub const EQUIVALENCE_UNVERIFIABLE: &str = "FA-REF-033";
    /// The entry cites fewer admissible documents than its class's `evidence_policy.toml` minimum.
    pub const EVIDENCE_MINIMUM: &str = "FA-REF-080";
    /// A citation names a document this book does not hold.
    pub const EVIDENCE_UNKNOWN: &str = "FA-REF-081";
    /// A citation's `doc_commit` is not the named document's commitment.
    pub const EVIDENCE_COMMIT: &str = "FA-REF-082";
    /// The document is empty, oversized, or names an unregistered kind, grade, or malformed mime.
    pub const DOCUMENT_INTAKE: &str = "FA-REF-083";
    /// The declared provenance grade is one only a verified receipt chain may confer.
    pub const GRADE_UNVERIFIED: &str = "FA-REF-084";
    /// A stored Document's mirrors disagree with its payload, or its payload does not verify.
    pub const DOCUMENT_DRIFT: &str = "FA-REF-085";
    /// The minimum is met only by counting self-sourced documents no reviewer other than the uploader has attested.
    pub const SELF_SOURCED: &str = "FA-REF-086";
    /// Supplemental evidence names an entry that is missing, not an Entry, or whose digest mismatches.
    pub const SUPPLEMENT_TARGET: &str = "FA-REF-087";
    /// `ErasureCut` is a registered absence: the substrate's erasure tombstones are not live (R-ERASE).
    pub const ERASURE_ABSENT: &str = "FA-REF-088";
    /// An attestation's subject is not one its claim can bind: a Reviewed names a document this book does not hold, or a ManualAssertion's class does not admit one.
    pub const ATTESTATION_SUBJECT: &str = "FA-REF-110";
    /// The reviewer of a document is the principal that uploaded it (SoD).
    pub const SELF_REVIEW: &str = "FA-REF-111";
    /// A ManualAssertion's reason code is not registered in `reason_codes.toml`.
    pub const REASON_CODE: &str = "FA-REF-112";
    /// A stored Attestation does not verify, its mirrors disagree with its payload, or it breaks a law its recording enforces.
    pub const ATTESTATION_DRIFT: &str = "FA-REF-113";
    /// The entry moves value out of a limited account below its lower bound
    /// (`net − pending_out − x < lower_bound`, plan §5.4).
    pub const AVAILABILITY_LOWER: &str = "FA-REF-090";
    /// The entry moves value into a limited account above its upper bound
    /// (`net + pending_in + x > upper_bound`, plan §5.4).
    pub const AVAILABILITY_UPPER: &str = "FA-REF-091";
    /// A limited account's posted or reserved total would leave the `i128`
    /// register ceiling.
    pub const LIMIT_CEILING: &str = "FA-REF-092";
    /// A balancing request is not the two-leg single-unit shape (plan §5.5),
    /// or its `fa:balancing:v1` extension is malformed or disagrees with the legs.
    pub const BALANCING_SHAPE: &str = "FA-REF-093";
    /// A TimeEvidence tick does not strictly follow the book's latest tick
    /// (plan §7.1a).
    pub const TICK_ORDER: &str = "FA-REF-094";
    /// A timed `Pending` has no committed TimeEvidence tick to anchor its
    /// deadline (plan §5.4).
    pub const TICK_MISSING: &str = "FA-REF-095";
    /// A timed `Pending`'s deadline (anchor tick + `timeout_ns`) leaves `u64`.
    pub const DEADLINE_OVERFLOW: &str = "FA-REF-096";
    /// A `Resolution(Posts)` names a hold a committed tick has already made due
    /// (`observed_utc_ns ≥ deadline`, plan §5.4).
    pub const HOLD_DUE: &str = "FA-REF-097";
    /// A `Resolution(Expires)` was submitted through `post`; only the expiry
    /// sweep mints one (plan §5.4).
    pub const EXPIRES_BY_SWEEP: &str = "FA-REF-098";
    /// A `ScheduleControl` entry was submitted through `post`; the kernel
    /// journals a schedule's cancellation itself, in the commit of the manual
    /// Reversal that supersedes the scheduled target (plan §7.6).
    pub const CANCEL_BY_KERNEL: &str = "FA-REF-099";
    /// A leg in a book that declares more than one legal entity names none
    /// (plan §4.1, §5.2: `legal_entity` is a mandatory balancing dimension).
    pub const DIMENSION_MISSING: &str = "FA-REF-005";
    /// A leg names a legal-entity value the book has not declared.
    pub const ENTITY_UNDECLARED: &str = "FA-REF-104";
    /// The migration run is not `Open`: it was finalized or abandoned, so it
    /// takes no more chunks and no second Finalize or Abandon (plan §8.6).
    pub const RUN_NOT_OPEN: &str = "FA-REF-130";
    /// The fold of a run's committed entries is not exactly the trial
    /// balance its body declares, or the declared balance does not balance
    /// (plan §8.6 tie-out).
    pub const TIE_OUT_MISMATCH: &str = "FA-REF-131";
    /// A `Migration` entry outside its run's law: no run named, an unknown
    /// run, a date other than the run's opening date, or a period other than
    /// its Opening period; or migration provenance on another class.
    pub const MIGRATION_OUTSIDE_RUN: &str = "FA-REF-132";
    /// A scratch replay met history it does not reproduce: a row family fa
    /// never writes, a property removal, a source window that does not reach
    /// genesis, or a divergence (plan §15.2).
    pub const REPLAY_UNSUPPORTED: &str = "FA-REF-134";
}

/// A foundation failure. Exit 5; never partial.
#[derive(Debug)]
pub enum KernelError {
    Write(fgdb::WriteError),
    Txn(fgdb::WriteTxnError),
    Read(fgdb::ReadError),
    Model(fa_model::EntryError),
    Mirror(fa_model::MirrorError),
    Date(fa_time::DateError),
    /// A stored row is not decodable as the schema it claims.
    Corrupt(String),
    /// A mirror value could not be built as a substrate scalar.
    Scalar(&'static str),
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(e) => write!(f, "substrate write: {e:?}"),
            Self::Txn(e) => write!(f, "substrate transaction: {e:?}"),
            Self::Read(e) => write!(f, "substrate read: {e:?}"),
            Self::Model(e) => write!(f, "model: {e}"),
            Self::Mirror(e) => write!(f, "mirror: {e}"),
            Self::Date(e) => write!(f, "date: {e:?}"),
            Self::Corrupt(what) => write!(f, "corrupt row: {what}"),
            Self::Scalar(what) => write!(f, "cannot build scalar `{what}`"),
        }
    }
}

impl core::error::Error for KernelError {}

impl From<fgdb::WriteError> for KernelError {
    fn from(e: fgdb::WriteError) -> Self {
        Self::Write(e)
    }
}
impl From<fgdb::WriteTxnError> for KernelError {
    fn from(e: fgdb::WriteTxnError) -> Self {
        Self::Txn(e)
    }
}
impl From<fgdb::ReadError> for KernelError {
    fn from(e: fgdb::ReadError) -> Self {
        Self::Read(e)
    }
}
impl From<fa_model::EntryError> for KernelError {
    fn from(e: fa_model::EntryError) -> Self {
        Self::Model(e)
    }
}
impl From<fa_model::MirrorError> for KernelError {
    fn from(e: fa_model::MirrorError) -> Self {
        Self::Mirror(e)
    }
}
impl From<fa_time::DateError> for KernelError {
    fn from(e: fa_time::DateError) -> Self {
        Self::Date(e)
    }
}

/// The kernel's result shape: a foundation failure, or a lawful refusal, or
/// the outcome.
pub type Outcome<T> = Result<Result<T, Refusal>, KernelError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_classes_match_registry() {
        let reg = fa_registry::ExitCodes::embedded().unwrap();
        assert_eq!(reg.code("success"), Some(exit::SUCCESS));
        assert_eq!(reg.code("usage"), Some(exit::USAGE));
        assert_eq!(reg.code("refusal"), Some(exit::REFUSAL));
        assert_eq!(reg.code("environment"), Some(exit::ENVIRONMENT));
        assert_eq!(reg.code("foundation"), Some(exit::FOUNDATION));
        assert_eq!(reg.code("conflict"), Some(exit::CONFLICT));
        assert_eq!(reg.code("safety"), Some(exit::SAFETY));
        assert_eq!(reg.code("verification"), Some(exit::VERIFICATION));
    }
}
