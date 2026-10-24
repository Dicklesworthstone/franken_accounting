//! Canon (plan §10.3): posting rules as a small, statically typed, total,
//! pure language. A rule maps one recorded REA event, plus explicitly
//! declared inputs, to candidate legs.
//!
//! This is a laws-layer crate: pure functions of explicit inputs. It reads no
//! clock, no storage, no entropy, and takes no `Cx` (the crate's
//! `clippy.toml` bans the ambient ones); "today" reaches a rule only as a
//! declared `date` input. Nothing here calls up.
//!
//! - [`compile`] parses a source, type-checks units, resolves every rounding
//!   law against the registered set and proves, per unit, that the debit and
//!   credit expressions are equal as exact linear forms. A rule the checker
//!   cannot prove balanced is refused; no residual leg is ever invented.
//! - [`CompiledRule`] carries the typed IR, its canonical bytes
//!   (`fa:canon-ir:v1`), the content address a `RuleVersion` journals, and
//!   the rule's static dependency set.
//! - [`evaluate`] is the interim tree-walking evaluator over that IR. It is
//!   total: every failure is a typed [`EvalError`], never a guess.
//!
//! Totality is by construction: no loops, no recursion, and a `let` may
//! name only the lets before it.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod check;
mod eval;
mod ir;
mod lex;
mod parse;
mod proof;

use core::fmt;

pub use check::compile;
pub use eval::{
    Derivation, DerivedLeg, EvalError, InputValue, Inputs, decode_inputs, encode_inputs, evaluate,
};
pub use ir::{
    CANON_INPUTS_DOMAIN, CANON_IR_DOMAIN, CompiledRule, DateSource, Dependencies, InputDecl,
    InputType, IrError, LegTemplate, Node, Produces,
};
pub use lex::MAX_SOURCE_BYTES;

/// A source the compiler refuses, at the line and column it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonError {
    pub line: u32,
    pub column: u32,
    pub message: String,
}

impl CanonError {
    pub(crate) fn new(line: u32, column: u32, message: impl Into<String>) -> Self {
        Self {
            line,
            column,
            message: message.into(),
        }
    }
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl core::error::Error for CanonError {}
