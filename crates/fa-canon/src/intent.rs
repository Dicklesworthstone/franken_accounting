//! Typed entry intents bound to Canon rule families (plan §10.2).
//!
//! Accrue and Defer both invoke the Adjusting family. Its existing IR binds
//! the produced class, output authority, effective date and optional reversal;
//! selecting a business verb preserves that rule's bytes and derivation identity.
//! Family validation precedes evaluation. Posting still needs the native
//! activation, reproduction, authority and accounting-law checks.

use core::fmt;

use crate::{CompiledRule, Produces};

/// The business intents currently backed by an existing Canon rule family.
/// The caller explicitly selects a rule version and supplies its declared
/// inputs; the selected rule must produce the family's admitted entry class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleIntentKind {
    Accrue,
    Defer,
}

impl RuleIntentKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Accrue => "Accrue",
            Self::Defer => "Defer",
        }
    }

    #[must_use]
    pub const fn required_produces(self) -> Produces {
        match self {
            Self::Accrue | Self::Defer => Produces::Adjusting,
        }
    }

    /// Check the selected rule's source-bound output class before deriving
    /// an entry. A rule's name and event kind cannot substitute for its class.
    /// This check grants no authority and does not supply or alter any input.
    pub fn validate_rule(self, rule: &CompiledRule) -> Result<(), RuleIntentError> {
        if rule.produces() == self.required_produces() {
            Ok(())
        } else {
            Err(RuleIntentError {
                intent: self,
                actual_produces: rule.produces(),
            })
        }
    }
}

/// The selected rule cannot implement the requested business intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleIntentError {
    pub intent: RuleIntentKind,
    pub actual_produces: Produces,
}

impl fmt::Display for RuleIntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} requires an {}-producing rule from the adjusting family; the selected rule produces {}",
            self.intent.name(),
            self.intent.required_produces().name(),
            self.actual_produces.name(),
        )
    }
}

impl core::error::Error for RuleIntentError {}
