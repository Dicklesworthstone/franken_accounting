//! The checker: names, unit types, registered laws and dimensions, and the
//! balance proof (plan §10.5).
//!
//! Every amount expression normalizes to an exact linear form over opaque
//! atoms: an event resource, a declared amount input, or one rounded
//! division (identified by the form it divides, its ratio and its law, so
//! the same rounding written twice is the same atom). Addition, subtraction
//! and integer scaling are linear; a rounded division is not, so it stays an
//! atom. A rule compiles only when, for every unit, its debit forms minus
//! its credit forms is the zero form. Evaluation is then balanced for every
//! event and every input, because each leg is the exact value of its form.

use std::collections::BTreeMap;

use crate::CanonError;
use crate::ir::{
    CompiledRule, DateSource, Dependencies, InputDecl, InputType, LegTemplate, Node, Parts, UnitRef,
};
use crate::parse::{self, DateRef, Expr, Pos, SourceType, Stmt};
use fa_model::{EventKind, dimension_kind};
use fa_money::{Amount, AmountError, RoundingLaw, Side, UnitId, UnitRegistry};

/// Parse, check and seal one rule source against the book's unit registry.
pub fn compile(source: &str, units: &UnitRegistry) -> Result<CompiledRule, CanonError> {
    let rule = parse::parse(source)?;
    let event = EventKind::from_name(&rule.event.0).ok_or_else(|| {
        rule.event.1.error(format!(
            "`{}` is not a registered event kind; one of {}",
            rule.event.0,
            EventKind::ALL
                .iter()
                .map(|k| k.name())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    let mut checker = Checker {
        units,
        inputs: Vec::new(),
        slots: Vec::new(),
        names: BTreeMap::new(),
        unit_refs: BTreeMap::new(),
        deps: Dependencies::default(),
    };
    for input in &rule.inputs {
        let ty = match &input.ty {
            SourceType::Date => InputType::Date,
            SourceType::Amount(unit, pos) => InputType::Amount(checker.unit(unit, *pos)?),
        };
        let index =
            u32::try_from(checker.inputs.len()).map_err(|_| input.pos.error("too many inputs"))?;
        checker.bind(&input.name, Bound::Input(index), input.pos)?;
        checker.inputs.push(InputDecl {
            name: input.name.clone(),
            ty,
        });
    }
    let mut legs = Vec::new();
    let mut balance: BTreeMap<UnitId, Form> = BTreeMap::new();
    let mut effective: Option<DateSource> = None;
    let start = Pos { line: 1, column: 1 };
    for stmt in &rule.stmts {
        match stmt {
            Stmt::Let { name, expr, pos } => {
                let typed = checker.amount(expr)?;
                let index =
                    u32::try_from(checker.slots.len()).map_err(|_| pos.error("too many lets"))?;
                checker.bind(name, Bound::Slot(index), *pos)?;
                checker.slots.push(typed);
            }
            Stmt::Leg {
                side,
                account,
                amount,
                dims,
                pos,
            } => {
                if account.trim().is_empty() || account.trim() != account {
                    return Err(pos.error("a leg names its account code without spaces around it"));
                }
                let typed = checker.amount(amount)?;
                let mut tagged: Vec<(u32, String, String)> = Vec::new();
                for (dimension, code, dim_pos) in dims {
                    let kind = dimension_kind(dimension).ok_or_else(|| {
                        dim_pos.error(format!(
                            "`{dimension}` is not a registered dimension; one of {}",
                            fa_model::DIMENSION_KINDS
                                .iter()
                                .map(|k| k.code)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                    })?;
                    if code.trim().is_empty() {
                        return Err(dim_pos.error("a dimension tag names a value code"));
                    }
                    if tagged.iter().any(|(id, ..)| *id == kind.id) {
                        return Err(dim_pos.error(format!("`{dimension}` is tagged twice")));
                    }
                    checker
                        .deps
                        .dimensions
                        .insert((dimension.clone(), code.clone()));
                    tagged.push((kind.id, dimension.clone(), code.clone()));
                }
                tagged.sort();
                checker.deps.accounts.insert(account.clone());
                let entry = balance.entry(typed.unit).or_default();
                *entry = entry
                    .combine(&typed.form, *side == Side::Debit)
                    .ok_or_else(|| pos.error("the rule's balance coefficients overflow"))?;
                legs.push(LegTemplate {
                    side: *side,
                    account: account.clone(),
                    unit: typed.unit,
                    amount: typed.node,
                    dims: tagged
                        .into_iter()
                        .map(|(_, dimension, code)| (dimension, code))
                        .collect(),
                });
            }
            Stmt::Effective { date, pos } => {
                if effective.is_some() {
                    return Err(pos.error("a rule names its effective date once"));
                }
                effective = Some(match date {
                    DateRef::Occurred => DateSource::Occurred,
                    DateRef::Name(name) => match checker.names.get(name) {
                        Some(Bound::Input(index))
                            if checker.inputs[*index as usize].ty == InputType::Date =>
                        {
                            DateSource::Input(*index)
                        }
                        _ => {
                            return Err(pos.error(format!(
                                "`{name}` is not a declared date input; declare it as `inputs {{ {name}: date }}`"
                            )));
                        }
                    },
                });
            }
        }
    }
    if !legs.iter().any(|l| l.side == Side::Debit) || !legs.iter().any(|l| l.side == Side::Credit) {
        return Err(start.error("a rule derives at least one debit and one credit"));
    }
    for (unit, form) in &balance {
        if !form.is_zero() {
            return Err(start.error(format!(
                "the rule does not balance in {}: debits minus credits is {}; every rule proves its debits equal its credits per unit, and Canon never adds a residual leg",
                checker.unit_refs[unit].spelling(),
                form.render(&checker.unit_refs),
            )));
        }
    }
    let Checker {
        inputs,
        slots,
        unit_refs,
        deps,
        ..
    } = checker;
    CompiledRule::seal(Parts {
        name: rule.name,
        version: rule.version,
        event,
        inputs,
        slots: slots.into_iter().map(|t| t.node).collect(),
        legs,
        effective: effective.unwrap_or(DateSource::Occurred),
        units: unit_refs,
        dependencies: deps,
    })
    .map_err(|e| start.error(format!("the rule's IR does not encode: {e}")))
}

#[derive(Clone, Copy, Debug)]
enum Bound {
    Input(u32),
    Slot(u32),
}

/// An amount expression after checking: its IR, unit and linear form.
#[derive(Clone, Debug)]
struct Typed {
    node: Node,
    unit: UnitId,
    form: Form,
}

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

    fn render(&self, units: &BTreeMap<UnitId, UnitRef>) -> String {
        let mut parts: Vec<String> = self
            .terms
            .iter()
            .map(|(atom, c)| {
                let what = match atom {
                    Atom::Resource(label, unit) => {
                        format!(
                            "event.resource(\"{label}\", \"{}\")",
                            units[unit].spelling()
                        )
                    }
                    Atom::Input(index) => format!("input #{index}"),
                    Atom::Rounded(form, num, den, law) => format!(
                        "({}) * {num} / {den} round {}",
                        form.render(units),
                        RoundingLaw::from_id(*law).map_or("?", RoundingLaw::name)
                    ),
                };
                format!("{c}·{what}")
            })
            .collect();
        if self.constant != 0 || parts.is_empty() {
            parts.push(format!("{} (minor units)", self.constant));
        }
        parts.join(" + ")
    }
}

struct Checker<'a> {
    units: &'a UnitRegistry,
    inputs: Vec<InputDecl>,
    slots: Vec<Typed>,
    names: BTreeMap<String, Bound>,
    unit_refs: BTreeMap<UnitId, UnitRef>,
    deps: Dependencies,
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while let Some(r) = a.checked_rem(b) {
        a = b;
        b = r;
    }
    a
}

impl Checker<'_> {
    fn bind(&mut self, name: &str, bound: Bound, pos: Pos) -> Result<(), CanonError> {
        if self.names.insert(name.to_string(), bound).is_some() {
            return Err(pos.error(format!(
                "`{name}` is already bound; a rule binds each name once"
            )));
        }
        Ok(())
    }

    fn unit(&mut self, spelling: &str, pos: Pos) -> Result<UnitId, CanonError> {
        let id = self.units.lookup(spelling).ok_or_else(|| {
            pos.error(format!("unit `{spelling}` is not registered in this book"))
        })?;
        self.note_unit(id, pos)
    }

    fn note_unit(&mut self, id: UnitId, pos: Pos) -> Result<UnitId, CanonError> {
        let unit = self
            .units
            .get(id)
            .ok_or_else(|| pos.error(format!("unit #{} is not registered", id.0)))?;
        let unit = UnitRef {
            code: unit.code.clone(),
            version: unit.version,
            scale: unit.scale,
        };
        self.deps.units.insert(unit.spelling());
        self.unit_refs.insert(id, unit);
        Ok(id)
    }

    fn amount(&mut self, expr: &Expr) -> Result<Typed, CanonError> {
        match expr {
            Expr::Literal(text, pos) => {
                let amount = Amount::parse(text, self.units).map_err(|e| {
                    pos.error(match e {
                        AmountError::UnknownUnit(unit) => {
                            format!("unit `{unit}` is not registered in this book")
                        }
                        AmountError::ExceedsScale { digits, scale } => format!(
                            "`{text}` has {digits} fractional digits; its unit carries {scale}"
                        ),
                        _ => format!("`{text}` is not an amount such as \"12.50 USD\""),
                    })
                })?;
                let unit = self.note_unit(amount.unit, *pos)?;
                Ok(Typed {
                    node: Node::Literal {
                        unit,
                        mantissa: amount.mantissa,
                    },
                    unit,
                    form: Form {
                        terms: BTreeMap::new(),
                        constant: amount.mantissa,
                    },
                })
            }
            Expr::Name(name, pos) => match self.names.get(name).copied() {
                Some(Bound::Slot(index)) => {
                    let slot = &self.slots[index as usize];
                    Ok(Typed {
                        node: Node::Slot(index),
                        unit: slot.unit,
                        form: slot.form.clone(),
                    })
                }
                Some(Bound::Input(index)) => match self.inputs[index as usize].ty {
                    InputType::Amount(unit) => Ok(Typed {
                        node: Node::Input(index),
                        unit,
                        form: Form::atom(Atom::Input(index)),
                    }),
                    InputType::Date => Err(pos.error(format!(
                        "`{name}` is a date input; an amount is expected here"
                    ))),
                },
                None => Err(pos.error(format!(
                    "`{name}` is not a let or a declared input; a rule reads only its event, its declared inputs and the lets before it (declare it as `inputs {{ {name}: date }}` or `amount(\"UNIT\")`)"
                ))),
            },
            Expr::Resource { label, unit, pos } => {
                if label.is_empty() {
                    return Err(pos.error("a resource label is not empty"));
                }
                let unit = self.unit(unit, *pos)?;
                self.deps
                    .resources
                    .insert((label.clone(), self.unit_refs[&unit].spelling()));
                Ok(Typed {
                    node: Node::Resource {
                        label: label.clone(),
                        unit,
                    },
                    unit,
                    form: Form::atom(Atom::Resource(label.clone(), unit)),
                })
            }
            Expr::Add(left, right) | Expr::Sub(left, right) => {
                let add = matches!(expr, Expr::Add(..));
                let l = self.amount(left)?;
                let r = self.amount(right)?;
                let pos = expr_pos(right);
                if l.unit != r.unit {
                    return Err(pos.error(format!(
                        "a {} amount cannot be {} a {} amount; units convert only under a named FX law",
                        self.unit_refs[&r.unit].spelling(),
                        if add { "added to" } else { "subtracted from" },
                        self.unit_refs[&l.unit].spelling(),
                    )));
                }
                let form = l
                    .form
                    .combine(&r.form, add)
                    .ok_or_else(|| pos.error("the expression's coefficients overflow"))?;
                let (a, b) = (Box::new(l.node), Box::new(r.node));
                Ok(Typed {
                    node: if add { Node::Add(a, b) } else { Node::Sub(a, b) },
                    unit: l.unit,
                    form,
                })
            }
            Expr::Scale {
                operand,
                factors,
                law,
                pos,
            } => {
                let inner = self.amount(operand)?;
                let (mut num, mut den) = (1u128, 1u128);
                for (multiply, n) in factors {
                    if *n == 0 {
                        return Err(pos.error(if *multiply {
                            "scaling by zero derives nothing; drop the leg instead"
                        } else {
                            "division by zero"
                        }));
                    }
                    let target = if *multiply { &mut num } else { &mut den };
                    *target = target
                        .checked_mul(u128::from(*n))
                        .ok_or_else(|| pos.error("the ratio overflows u128"))?;
                }
                let divides = factors.iter().any(|(multiply, _)| !multiply);
                let divisor = gcd(num, den);
                let (num, den) = (
                    num.checked_div(divisor).unwrap_or(num),
                    den.checked_div(divisor).unwrap_or(den),
                );
                let law = match law {
                    Some((name, law_pos)) => {
                        if !divides {
                            return Err(law_pos.error(
                                "`round` names the law of a division, and this term divides nothing",
                            ));
                        }
                        Some(RoundingLaw::from_name(name).ok_or_else(|| {
                            law_pos.error(format!(
                                "`{name}` is not a registered rounding law; one of {}",
                                RoundingLaw::ALL
                                    .iter()
                                    .map(|l| l.name())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ))
                        })?)
                    }
                    None if divides => {
                        return Err(pos.error(
                            "a division names its rounding law: `… / D round HalfEven`",
                        ));
                    }
                    None => None,
                };
                if den == 1 {
                    let form = inner
                        .form
                        .times(num)
                        .ok_or_else(|| pos.error("the expression's coefficients overflow"))?;
                    let node = if num == 1 {
                        inner.node
                    } else {
                        Node::Scale {
                            operand: Box::new(inner.node),
                            num,
                            den,
                            law: None,
                        }
                    };
                    return Ok(Typed {
                        node,
                        unit: inner.unit,
                        form,
                    });
                }
                let law = law.ok_or_else(|| pos.error("a division names its rounding law"))?;
                self.deps.laws.insert(law.name().to_string());
                Ok(Typed {
                    form: Form::atom(Atom::Rounded(
                        Box::new(inner.form),
                        num,
                        den,
                        law.id(),
                    )),
                    node: Node::Scale {
                        operand: Box::new(inner.node),
                        num,
                        den,
                        law: Some(law),
                    },
                    unit: inner.unit,
                })
            }
        }
    }
}

fn expr_pos(expr: &Expr) -> Pos {
    match expr {
        Expr::Literal(_, pos)
        | Expr::Name(_, pos)
        | Expr::Resource { pos, .. }
        | Expr::Scale { pos, .. } => *pos,
        Expr::Add(left, _) | Expr::Sub(left, _) => expr_pos(left),
    }
}
