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
    /// The idempotency key was reused with different content.
    pub const IDEMPOTENCY_CONFLICT: &str = "FA-REF-032";
    /// A Reversal names no target, a target that does not exist, or a digest that does not match.
    pub const REVERSAL_TARGET: &str = "FA-REF-050";
    /// A Reversal's legs are not the exact side-swap of the target's legs.
    pub const REVERSAL_SHAPE: &str = "FA-REF-051";
    /// The target is already reversed by another entry.
    pub const ALREADY_REVERSED: &str = "FA-REF-052";
    /// A key collided but equivalence cannot be verified: a sealed field is erased or under a key this book lacks.
    pub const EQUIVALENCE_UNVERIFIABLE: &str = "FA-REF-033";
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
