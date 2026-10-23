//! The balance proof (plan §10.5), over the IR itself, so a rule decoded
//! from the journal is proven exactly as a rule compiled from source is.
//!
//! Every amount node normalizes to an exact linear form over opaque atoms:
//! an event resource, a declared amount input, or one rounded division
//! (identified by the form it divides, its reduced ratio and its law, so the
//! same rounding written twice is the same atom). Addition, subtraction and
//! integer scaling are linear; a rounded division is not, so it stays an
//! atom. A rule is proven when, for every unit, its debit forms minus its
//! credit forms is the zero form. Evaluation is then balanced for every
//! event and every input, because each leg is the exact value of its form
//! and equal atoms evaluate equally.

use std::collections::BTreeMap;

use crate::ir::{Node, Parts, UnitRef};
use fa_money::{RoundingLaw, Side, UnitId};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Atom {
    Resource(String, UnitId),
    Input(u32),
    Rounded(Box<Form>, u128, u128, u16),
}

/// `constant + Σ coefficient·atom`, exact, with no zero coefficients.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Form {
    terms: BTreeMap<Atom, i128>,
    constant: i128,
}

impl Form {
    fn atom(atom: Atom) -> Self {
        Self {
            terms: BTreeMap::from([(atom, 1)]),
            constant: 0,
        }
    }

    fn is_zero(&self) -> bool {
        self.constant == 0 && self.terms.is_empty()
    }

    /// `self + other` (`add`) or `self − other`.
    fn combine(&self, other: &Self, add: bool) -> Option<Self> {
        let op = |a: i128, b: i128| {
            if add {
                a.checked_add(b)
            } else {
                a.checked_sub(b)
            }
        };
        let mut out = self.clone();
        out.constant = op(out.constant, other.constant)?;
        for (atom, coefficient) in &other.terms {
            let current = out.terms.get(atom).copied().unwrap_or(0);
            let next = op(current, *coefficient)?;
            if next == 0 {
                out.terms.remove(atom);
            } else {
                out.terms.insert(atom.clone(), next);
            }
        }
        Some(out)
    }

    fn times(&self, factor: u128) -> Option<Self> {
        let factor = i128::try_from(factor).ok()?;
        Some(Self {
            constant: self.constant.checked_mul(factor)?,
            terms: self
                .terms
                .iter()
                .map(|(atom, c)| Some((atom.clone(), c.checked_mul(factor)?)))
                .collect::<Option<_>>()?,
        })
    }

    fn render(&self, parts: &Parts) -> String {
        let mut out: Vec<String> = self
            .terms
            .iter()
            .map(|(atom, c)| {
                let what = match atom {
                    Atom::Resource(label, unit) => format!(
                        "event.resource(\"{label}\", \"{}\")",
                        parts
                            .units
                            .get(unit)
                            .map_or_else(String::new, UnitRef::spelling)
                    ),
                    Atom::Input(index) => parts
                        .inputs
                        .get(*index as usize)
                        .map_or_else(|| format!("input #{index}"), |input| input.name.clone()),
                    Atom::Rounded(form, num, den, law) => format!(
                        "({}) * {num} / {den} round {}",
                        form.render(parts),
                        RoundingLaw::from_id(*law).map_or("?", RoundingLaw::name)
                    ),
                };
                format!("{c}·{what}")
            })
            .collect();
        if self.constant != 0 || out.is_empty() {
            out.push(format!("{} (minor units)", self.constant));
        }
        out.join(" + ")
    }
}

/// Why a rule is not proven balanced.
pub(crate) enum Unproven {
    /// Debits minus credits in `unit` is the nonzero form rendered.
    Unbalanced { unit: String, residual: String },
    /// A coefficient left the i128 range while normalizing.
    Overflow,
}

fn form(node: &Node, slots: &[Form]) -> Option<Form> {
    Some(match node {
        Node::Literal { mantissa, .. } => Form {
            terms: BTreeMap::new(),
            constant: *mantissa,
        },
        Node::Resource { label, unit } => Form::atom(Atom::Resource(label.clone(), *unit)),
        Node::Input(index) => Form::atom(Atom::Input(*index)),
        Node::Slot(index) => slots.get(*index as usize)?.clone(),
        Node::Add(left, right) => form(left, slots)?.combine(&form(right, slots)?, true)?,
        Node::Sub(left, right) => form(left, slots)?.combine(&form(right, slots)?, false)?,
        Node::Scale {
            operand,
            num,
            den,
            law,
        } => {
            let inner = form(operand, slots)?;
            match law {
                // A whole ratio is exact, so it scales the form linearly.
                None => inner.times(*num)?,
                Some(law) => Form::atom(Atom::Rounded(Box::new(inner), *num, *den, law.id())),
            }
        }
    })
}

/// Prove that every unit's debits equal its credits as exact linear forms.
/// `parts` is structurally valid (see `ir::validate`).
pub(crate) fn prove(parts: &Parts) -> Result<(), Unproven> {
    let mut slots: Vec<Form> = Vec::with_capacity(parts.slots.len());
    for node in &parts.slots {
        slots.push(form(node, &slots).ok_or(Unproven::Overflow)?);
    }
    let mut balance: BTreeMap<UnitId, Form> = BTreeMap::new();
    for leg in &parts.legs {
        let leg_form = form(&leg.amount, &slots).ok_or(Unproven::Overflow)?;
        let entry = balance.entry(leg.unit).or_default();
        *entry = entry
            .combine(&leg_form, leg.side == Side::Debit)
            .ok_or(Unproven::Overflow)?;
    }
    for (unit, residual) in &balance {
        if !residual.is_zero() {
            return Err(Unproven::Unbalanced {
                unit: parts
                    .units
                    .get(unit)
                    .map_or_else(|| format!("#{}", unit.0), UnitRef::spelling),
                residual: residual.render(parts),
            });
        }
    }
    Ok(())
}
