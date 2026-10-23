//! Canon posting rules on the facade (plan §10.3, bead fa-c34). A rule is
//! compiled against the book's unit registry and evaluated over a recorded
//! REA event by [`fa_canon`], which is pure: this module adds only the book's
//! units and the refusal envelope.
//!
//! Nothing here writes. A derivation names the legs a rule version would
//! give an event; journaled rule versions, their activation and
//! rule-derived posting are later slices of the bead.

use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};

pub use fa_canon::{
    CanonError, CompiledRule, Dependencies, Derivation, DerivedLeg, EvalError, InputDecl,
    InputType, InputValue, Inputs, MAX_SOURCE_BYTES, evaluate,
};

pub mod code {
    /// A rule source the Canon checker refuses (a parse, unit, law, name or
    /// balance-proof failure), or an evaluation that cannot be computed
    /// exactly over the event it was given.
    pub const CANON_RULE: &str = "FA-REF-196";
}

const CITE: &str = "plan §10.3 (Canon: a total, statically typed rule language; units, laws and balance are checked before a rule runs)";
const EVAL_CITE: &str = "plan §10.3 (a rule that cannot be evaluated fails closed with a typed error instead of posting a guess)";

/// Compile `source` against this book's registered units.
pub fn compile_rule(context: &BookContext, source: &str) -> Result<CompiledRule, Refusal> {
    fa_canon::compile(source, &context.units).map_err(|error| rule_refusal(&error))
}

/// The refusal for a source the checker rejects, at the line and column it
/// names.
#[must_use]
pub fn rule_refusal(error: &CanonError) -> Refusal {
    Refusal::new(
        code::CANON_RULE,
        exit::REFUSAL,
        format!(
            "the rule is refused at line {}, column {}: {}",
            error.line, error.column, error.message
        ),
        CITE,
        "revise the rule at that line and column, then run fa rule check <file> again",
    )
    .at("rule", format!("{}:{}", error.line, error.column))
}

/// The refusal for an evaluation that cannot be computed over this event.
#[must_use]
pub fn evaluation_refusal(rule: &CompiledRule, event: &str, error: &EvalError) -> Refusal {
    let fix = match error {
        EvalError::WrongEventKind { rule, .. } => {
            format!("evaluate the rule over a {} event (fa event list)", rule.name())
        }
        EvalError::MissingResource { .. } | EvalError::AmbiguousResource { .. } => {
            "evaluate an event that carries each resource the rule reads exactly once (fa event show <code>), or revise the rule".to_string()
        }
        EvalError::ResourceUnit { .. } => {
            "read the resource in the unit the event records it in, or evaluate another event".to_string()
        }
        EvalError::MissingInput { name } => format!("supply --input {name}=<value>"),
        EvalError::UndeclaredInput { name } => {
            format!("drop --input {name}, or declare it in the rule's inputs block")
        }
        EvalError::InputType { name, .. } => {
            format!("supply --input {name}=<value> in the declared type")
        }
        EvalError::Overflow { .. } | EvalError::NegativeLeg { .. } | EvalError::Encode(_) => {
            "revise the rule so every leg is a non-negative amount within range for this event".to_string()
        }
    };
    Refusal::new(
        code::CANON_RULE,
        exit::REFUSAL,
        format!(
            "rule {} v{} cannot be evaluated over event {event}: {error}",
            rule.name(),
            rule.version()
        ),
        EVAL_CITE,
        fix,
    )
    .at("event", event)
}
