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
//!
//! A rounded division names the form it divides by its id in [`Forms`],
//! where every distinct form is stored once. Structurally equal forms get
//! the same id, so equality stays exact, and a `let` used twice shares one
//! entry instead of being copied: nesting lets no longer multiplies the
//! work. What remains grows with the distinct forms and terms a rule builds
//! (combining forms still clones and compares them), not with how often a
//! form is used.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::ir::{Node, Parts, UnitRef};
use fa_money::{RoundingLaw, Side, UnitId};

/// How much of a residual the refusal renders; the rest is elided. Each
/// open rounding still closes, so the text is at most this plus one closing
/// suffix per nesting level.
const MAX_RENDER: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Atom {
    Resource(String, UnitId),
    Input(u32),
    /// The form with this id in [`Forms`], times `num / den`, rounded by
    /// the law with this id.
    Rounded(u32, u128, u128, u16),
}

/// `constant + Σ coefficient·atom`, exact, with no zero coefficients.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Form {
    terms: BTreeMap<Atom, i128>,
    constant: i128,
}

/// Every distinct form a rounded division divides, stored once.
#[derive(Default)]
struct Forms {
    ids: BTreeMap<Form, u32>,
    all: Vec<Form>,
}

impl Forms {
    fn intern(&mut self, form: Form) -> Option<u32> {
        if let Some(id) = self.ids.get(&form) {
            return Some(*id);
        }
        let id = u32::try_from(self.all.len()).ok()?;
        self.all.push(form.clone());
        self.ids.insert(form, id);
        Some(id)
    }
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

    /// Append the form as text to `out`, eliding what follows once `out`
    /// holds [`MAX_RENDER`] bytes: a nested rounding written out in full can
    /// be far larger than its rule.
    fn render(&self, parts: &Parts, forms: &Forms, out: &mut String) {
        let mut first = true;
        for (atom, c) in &self.terms {
            if out.len() >= MAX_RENDER {
                out.push('…');
                return;
            }
            if !first {
                out.push_str(" + ");
            }
            first = false;
            let _ = write!(out, "{c}·");
            match atom {
                Atom::Resource(label, unit) => {
                    let _ = write!(
                        out,
                        "event.resource(\"{label}\", \"{}\")",
                        parts
                            .units
                            .get(unit)
                            .map_or_else(String::new, UnitRef::spelling)
                    );
                }
                Atom::Input(index) => match parts.inputs.get(*index as usize) {
                    Some(input) => out.push_str(&input.name),
                    None => {
                        let _ = write!(out, "input #{index}");
                    }
                },
                Atom::Rounded(id, num, den, law) => {
                    out.push('(');
                    match forms.all.get(*id as usize) {
                        Some(inner) => inner.render(parts, forms, out),
                        None => out.push('?'),
                    }
                    let _ = write!(
                        out,
                        ") * {num} / {den} round {}",
                        RoundingLaw::from_id(*law).map_or("?", RoundingLaw::name)
                    );
                }
            }
        }
        if self.constant != 0 || first {
            if !first {
                out.push_str(" + ");
            }
            let _ = write!(out, "{} (minor units)", self.constant);
        }
    }
}

/// Why a rule is not proven balanced.
pub(crate) enum Unproven {
    /// Debits minus credits in `unit` is the nonzero form rendered.
    Unbalanced { unit: String, residual: String },
    /// A coefficient left the i128 range while normalizing.
    Overflow,
}

fn form(node: &Node, slots: &[Form], forms: &mut Forms) -> Option<Form> {
    Some(match node {
        Node::Literal { mantissa, .. } => Form {
            terms: BTreeMap::new(),
            constant: *mantissa,
        },
        Node::Resource { label, unit } => Form::atom(Atom::Resource(label.clone(), *unit)),
        Node::Input(index) => Form::atom(Atom::Input(*index)),
        Node::Slot(index) => slots.get(*index as usize)?.clone(),
        Node::Add(left, right) => {
            form(left, slots, forms)?.combine(&form(right, slots, forms)?, true)?
        }
        Node::Sub(left, right) => {
            form(left, slots, forms)?.combine(&form(right, slots, forms)?, false)?
        }
        Node::Scale {
            operand,
            num,
            den,
            law,
        } => {
            let inner = form(operand, slots, forms)?;
            match law {
                // A whole ratio is exact, so it scales the form linearly.
                None => inner.times(*num)?,
                Some(law) => Form::atom(Atom::Rounded(forms.intern(inner)?, *num, *den, law.id())),
            }
        }
    })
}

/// Prove that every unit's debits equal its credits as exact linear forms.
/// `parts` is structurally valid (see `ir::validate`).
pub(crate) fn prove(parts: &Parts) -> Result<(), Unproven> {
    let mut forms = Forms::default();
    let mut slots: Vec<Form> = Vec::with_capacity(parts.slots.len());
    for node in &parts.slots {
        slots.push(form(node, &slots, &mut forms).ok_or(Unproven::Overflow)?);
    }
    let mut balance: BTreeMap<UnitId, Form> = BTreeMap::new();
    for leg in &parts.legs {
        let leg_form = form(&leg.amount, &slots, &mut forms).ok_or(Unproven::Overflow)?;
        let entry = balance.entry(leg.unit).or_default();
        *entry = entry
            .combine(&leg_form, leg.side == Side::Debit)
            .ok_or(Unproven::Overflow)?;
    }
    for (unit, residual) in &balance {
        if !residual.is_zero() {
            let mut rendered = String::new();
            residual.render(parts, &forms, &mut rendered);
            return Err(Unproven::Unbalanced {
                unit: parts
                    .units
                    .get(unit)
                    .map_or_else(|| format!("#{}", unit.0), UnitRef::spelling),
                residual: rendered,
            });
        }
    }
    Ok(())
}
