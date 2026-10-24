//! The interim evaluator (plan §10.3): a tree walk over the checked IR.
//! Every amount is exact; a rounded division applies its named law to the
//! exact quotient and remainder; anything that cannot be computed exactly is
//! a typed [`EvalError`], never a guess.

use core::fmt;
use std::collections::BTreeMap;

use crate::ir::{CANON_INPUTS_DOMAIN, CompiledRule, DateSource, InputType, Node, write_unit};
use fa_model::{EventKind, EventSpec, Reader, Writer, domain_digest};
use fa_money::wide::U256;
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputValue {
    Date(DateDay),
    Amount(Amount),
}

/// The values a caller supplies for a rule's declared inputs, by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inputs(BTreeMap<String, InputValue>);

impl Inputs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Supply `name`; a second value for the same name replaces the first.
    pub fn set(&mut self, name: impl Into<String>, value: InputValue) -> &mut Self {
        self.0.insert(name.into(), value);
        self
    }
}

/// One candidate leg: never negative, never zero (a zero leg is omitted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedLeg {
    pub side: Side,
    pub account: String,
    pub amount: Amount,
    /// `(dimension, value code)`, as the rule tags them.
    pub dims: Vec<(String, String)>,
}

/// What one rule version derives from one event and its inputs: the legs,
/// the effective date, and the three digests a rule-derived entry's origin
/// names (`EntryOrigin::Rule`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derivation {
    pub rule_version_oid: [u8; 32],
    pub event_digest: [u8; 32],
    pub inputs_digest: [u8; 32],
    pub effective: DateDay,
    /// When the entry reverses (an Adjusting rule's `reverses`): always
    /// after `effective`.
    pub reverse_on: Option<DateDay>,
    pub legs: Vec<DerivedLeg>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalError {
    WrongEventKind {
        rule: EventKind,
        event: EventKind,
    },
    MissingResource {
        label: String,
    },
    /// The event carries the label more than once, so the read is ambiguous.
    AmbiguousResource {
        label: String,
    },
    ResourceUnit {
        label: String,
        expected: UnitId,
        found: UnitId,
    },
    MissingInput {
        name: String,
    },
    UndeclaredInput {
        name: String,
    },
    InputType {
        name: String,
        expected: InputType,
    },
    /// An exact intermediate left the i128 range in the let or leg `at`.
    Overflow {
        at: String,
    },
    NegativeLeg {
        account: String,
        amount: Amount,
    },
    /// The reversal date is not after the effective date.
    ReversalNotAfter {
        effective: DateDay,
        reverse_on: DateDay,
    },
    Encode(String),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongEventKind { rule, event } => write!(
                f,
                "the rule derives from {} events, and this event is a {}",
                rule.name(),
                event.name()
            ),
            Self::MissingResource { label } => write!(
                f,
                "the event carries no resource labeled `{label}`; record it on the event, or evaluate a rule that does not read it"
            ),
            Self::AmbiguousResource { label } => write!(
                f,
                "the event carries more than one resource labeled `{label}`, so the rule's read is ambiguous"
            ),
            Self::ResourceUnit {
                label,
                expected,
                found,
            } => write!(
                f,
                "resource `{label}` is in unit #{}, and the rule reads it as unit #{}",
                found.0, expected.0
            ),
            Self::MissingInput { name } => {
                write!(
                    f,
                    "the rule declares input `{name}`; supply it with --input {name}=…"
                )
            }
            Self::UndeclaredInput { name } => write!(
                f,
                "the rule declares no input `{name}`; a rule reads only what it declares"
            ),
            Self::InputType { name, expected } => match expected {
                InputType::Date => write!(f, "input `{name}` is a date (YYYY-MM-DD)"),
                InputType::Amount(unit) => {
                    write!(f, "input `{name}` is an amount in unit #{}", unit.0)
                }
            },
            Self::Overflow { at } => write!(
                f,
                "the amount for {at} leaves the exact i128 range; nothing is clamped"
            ),
            Self::NegativeLeg { account, amount } => write!(
                f,
                "the leg on {account} evaluates to {} minor units below zero; a leg is never negative, so the rule must be revised for this event",
                amount.mantissa.unsigned_abs()
            ),
            Self::ReversalNotAfter {
                effective,
                reverse_on,
            } => write!(
                f,
                "the reversal date {} does not follow the effective date {}; a scheduled reversal comes after the entry it reverses",
                reverse_on.render(),
                effective.render()
            ),
            Self::Encode(message) => write!(f, "canonical encoding failed: {message}"),
        }
    }
}

impl core::error::Error for EvalError {}

struct Frame<'a> {
    rule: &'a CompiledRule,
    event: &'a EventSpec,
    inputs: &'a Inputs,
    slots: Vec<i128>,
}

/// The canonical bytes of `inputs` under `rule`'s declarations, in
/// declaration order (`str name ‖ u8 1 ‖ i32 day` for a date, `str name ‖ u8
/// 2 ‖ unit ‖ i128 mantissa` for an amount): what `inputs_digest` digests
/// and a rule-derived entry records, so the derivation can be re-run.
/// Every declared input must be supplied in its type, and no other.
pub fn encode_inputs(rule: &CompiledRule, inputs: &Inputs) -> Result<Vec<u8>, EvalError> {
    if let Some(name) = inputs
        .0
        .keys()
        .find(|name| !rule.inputs().iter().any(|decl| &decl.name == *name))
    {
        return Err(EvalError::UndeclaredInput { name: name.clone() });
    }
    let mut digest_input = Writer::new();
    for decl in rule.inputs() {
        let value = inputs
            .0
            .get(&decl.name)
            .ok_or_else(|| EvalError::MissingInput {
                name: decl.name.clone(),
            })?;
        digest_input.str(&decl.name);
        match (&decl.ty, value) {
            (InputType::Date, InputValue::Date(day)) => {
                digest_input.u8(1).i32(day.0);
            }
            (InputType::Amount(unit), InputValue::Amount(amount)) if amount.unit == *unit => {
                digest_input.u8(2);
                write_unit(&mut digest_input, rule.unit(*unit));
                digest_input.i128(amount.mantissa);
            }
            _ => {
                return Err(EvalError::InputType {
                    name: decl.name.clone(),
                    expected: decl.ty.clone(),
                });
            }
        }
    }
    digest_input
        .finish()
        .map_err(|e| EvalError::Encode(e.to_string()))
}

/// Read inputs back from their canonical bytes under `rule`'s declarations:
/// exactly the declared names in order, each in its declared type and unit.
pub fn decode_inputs(rule: &CompiledRule, bytes: &[u8]) -> Result<Inputs, EvalError> {
    let bad = |what: &str| EvalError::Encode(format!("rule inputs: {what}"));
    let mut r = Reader::new(bytes);
    let mut out = Inputs::new();
    for decl in rule.inputs() {
        let name = r
            .str(1024, "rule input name")
            .map_err(|e| bad(&e.to_string()))?;
        if name != decl.name {
            return Err(bad(&format!(
                "`{name}` is not the declared input `{}`",
                decl.name
            )));
        }
        let value = match (
            r.u8("rule input type").map_err(|e| bad(&e.to_string()))?,
            &decl.ty,
        ) {
            (1, InputType::Date) => InputValue::Date(DateDay(
                r.i32("rule input date").map_err(|e| bad(&e.to_string()))?,
            )),
            (2, InputType::Amount(unit)) => {
                let spelled = rule.unit(*unit);
                let code = r
                    .str(64, "rule input unit")
                    .map_err(|e| bad(&e.to_string()))?;
                let version = r
                    .u16("rule input unit version")
                    .map_err(|e| bad(&e.to_string()))?;
                let scale = r
                    .u8("rule input unit scale")
                    .map_err(|e| bad(&e.to_string()))?;
                if code != spelled.code || version != spelled.version || scale != spelled.scale {
                    return Err(bad(&format!(
                        "`{name}` is in another unit than the rule declares"
                    )));
                }
                let mantissa = r
                    .i128("rule input amount")
                    .map_err(|e| bad(&e.to_string()))?;
                InputValue::Amount(Amount::new(*unit, mantissa))
            }
            _ => return Err(bad(&format!("`{name}` is not in its declared type"))),
        };
        out.set(name, value);
    }
    r.finish().map_err(|e| bad(&e.to_string()))?;
    Ok(out)
}

/// Evaluate `rule` over `event` with `inputs`. Pure and total: the same
/// three arguments always yield the same [`Derivation`] or the same error.
pub fn evaluate(
    rule: &CompiledRule,
    event: &EventSpec,
    inputs: &Inputs,
) -> Result<Derivation, EvalError> {
    if event.kind != rule.event() {
        return Err(EvalError::WrongEventKind {
            rule: rule.event(),
            event: event.kind,
        });
    }
    let inputs_bytes = encode_inputs(rule, inputs)?;
    let event_digest = event
        .event_digest()
        .map_err(|e| EvalError::Encode(e.to_string()))?;
    let mut frame = Frame {
        rule,
        event,
        inputs,
        slots: Vec::with_capacity(rule.slots().len()),
    };
    for (index, node) in rule.slots().iter().enumerate() {
        let value = frame
            .value(node)
            .map_err(|e| e.at(&format!("let #{index}")))?;
        frame.slots.push(value);
    }
    let mut legs = Vec::new();
    for leg in rule.legs() {
        let mantissa = frame
            .value(&leg.amount)
            .map_err(|e| e.at(&format!("the leg on {}", leg.account)))?;
        let amount = Amount::new(leg.unit, mantissa);
        if mantissa < 0 {
            return Err(EvalError::NegativeLeg {
                account: leg.account.clone(),
                amount,
            });
        }
        if mantissa == 0 {
            continue;
        }
        legs.push(DerivedLeg {
            side: leg.side,
            account: leg.account.clone(),
            amount,
            dims: leg.dims.clone(),
        });
    }
    let date = |source: DateSource| match source {
        DateSource::Occurred => Ok(event.occurred_on),
        DateSource::Input(index) => match rule
            .inputs()
            .get(index as usize)
            .and_then(|decl| inputs.0.get(&decl.name))
        {
            Some(InputValue::Date(day)) => Ok(*day),
            _ => Err(EvalError::InputType {
                name: rule.inputs()[index as usize].name.clone(),
                expected: InputType::Date,
            }),
        },
    };
    let effective = date(rule.effective())?;
    let reverse_on = rule.reverses().map(date).transpose()?;
    if let Some(reverse_on) = reverse_on
        && reverse_on <= effective
    {
        return Err(EvalError::ReversalNotAfter {
            effective,
            reverse_on,
        });
    }
    Ok(Derivation {
        rule_version_oid: rule.ir_digest(),
        event_digest,
        inputs_digest: domain_digest(CANON_INPUTS_DOMAIN, &[&inputs_bytes]),
        effective,
        reverse_on,
        legs,
    })
}

/// A failure inside one value, before it is attributed to the leg or let
/// that asked for it.
enum Fault {
    Overflow,
    Error(EvalError),
}

impl Fault {
    fn at(self, at: &str) -> EvalError {
        match self {
            Self::Overflow => EvalError::Overflow { at: at.to_string() },
            Self::Error(e) => e,
        }
    }
}

impl Frame<'_> {
    fn value(&self, node: &Node) -> Result<i128, Fault> {
        match node {
            Node::Literal { mantissa, .. } => Ok(*mantissa),
            Node::Resource { label, unit } => {
                let mut found = self.event.resources.iter().filter(|r| &r.label == label);
                let resource = found.next().ok_or_else(|| {
                    Fault::Error(EvalError::MissingResource {
                        label: label.clone(),
                    })
                })?;
                if found.next().is_some() {
                    return Err(Fault::Error(EvalError::AmbiguousResource {
                        label: label.clone(),
                    }));
                }
                if resource.amount.unit != *unit {
                    return Err(Fault::Error(EvalError::ResourceUnit {
                        label: label.clone(),
                        expected: *unit,
                        found: resource.amount.unit,
                    }));
                }
                Ok(resource.amount.mantissa)
            }
            Node::Input(index) => {
                let name = &self.rule.inputs()[*index as usize].name;
                match self.inputs.0.get(name) {
                    Some(InputValue::Amount(amount)) => Ok(amount.mantissa),
                    _ => Err(Fault::Error(EvalError::MissingInput { name: name.clone() })),
                }
            }
            Node::Slot(index) => Ok(self.slots[*index as usize]),
            Node::Add(left, right) => self
                .value(left)?
                .checked_add(self.value(right)?)
                .ok_or(Fault::Overflow),
            Node::Sub(left, right) => self
                .value(left)?
                .checked_sub(self.value(right)?)
                .ok_or(Fault::Overflow),
            Node::Scale {
                operand,
                num,
                den,
                law,
            } => {
                let value = self.value(operand)?;
                let negative = value < 0;
                // Plan §6.1: the product and quotient stay wide; only the
                // term's rounded magnitude is narrowed. The remainder is
                // below the u128 divisor, and a quotient past u128 cannot
                // narrow to i128 at all.
                let product = U256::from_product(value.unsigned_abs(), *num);
                let (quotient, remainder) = product
                    .checked_div_rem(U256::from_u128(*den))
                    .ok_or(Fault::Overflow)?;
                let quotient = quotient.to_u128().ok_or(Fault::Overflow)?;
                let remainder = remainder.to_u128().ok_or(Fault::Overflow)?;
                let magnitude = match law {
                    Some(law) => law
                        .apply_magnitude(quotient, remainder, *den, negative)
                        .ok_or(Fault::Overflow)?,
                    // The checker sets no law only when the ratio is whole.
                    None if remainder == 0 => quotient,
                    None => return Err(Fault::Overflow),
                };
                // The sign is restored after narrowing, so i128::MIN stays
                // representable.
                if negative {
                    0i128.checked_sub_unsigned(magnitude).ok_or(Fault::Overflow)
                } else {
                    i128::try_from(magnitude).map_err(|_| Fault::Overflow)
                }
            }
        }
    }
}
