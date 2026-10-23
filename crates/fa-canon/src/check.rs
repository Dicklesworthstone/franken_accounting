//! The checker: names, unit types, registered laws, dimensions and event
//! kinds, from source to the typed IR. The balance proof and the IR's
//! structural law run in [`CompiledRule::seal`], over the IR itself, so a
//! rule decoded from the journal passes the same gate as one compiled here.

use std::collections::BTreeMap;

use crate::CanonError;
use crate::ir::{
    CompiledRule, DateSource, InputDecl, InputType, LegTemplate, Node, Parts, Produces, UnitRef,
    reduce,
};
use crate::parse::{self, DateRef, Expr, Pos, SourceType, Stmt};
use fa_model::{EventKind, dimension_kind};
use fa_money::{Amount, AmountError, RoundingLaw, UnitId, UnitRegistry};

/// Parse, check, prove and seal one rule source against the book's units.
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
    let produces = match &rule.produces {
        None => Produces::Original,
        Some((class, pos)) => Produces::from_name(class).ok_or_else(|| {
            let bound = Produces::ALL
                .iter()
                .map(|class| class.name())
                .collect::<Vec<_>>()
                .join(" or ");
            pos.error(if fa_model::EntryClass::from_name(class).is_some() {
                format!(
                    "a rule produces {bound} entries; {class} is not bound to a rule family yet (plan §10.2)"
                )
            } else {
                format!("`{class}` is not an entry class; a rule produces {bound} entries")
            })
        })?,
    };
    let mut checker = Checker {
        units,
        inputs: Vec::new(),
        slots: Vec::new(),
        names: BTreeMap::new(),
        unit_refs: BTreeMap::new(),
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
    let mut effective: Option<DateSource> = None;
    let mut reverses: Option<DateSource> = None;
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
                    if code.trim().is_empty() || code.trim() != code {
                        return Err(dim_pos
                            .error("a dimension tag names a value code without spaces around it"));
                    }
                    if tagged.iter().any(|(id, ..)| *id == kind.id) {
                        return Err(dim_pos.error(format!("`{dimension}` is tagged twice")));
                    }
                    tagged.push((kind.id, dimension.clone(), code.clone()));
                }
                tagged.sort();
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
                effective = Some(checker.date(date, *pos)?);
            }
            Stmt::Reverses { date, pos } => {
                if reverses.is_some() {
                    return Err(pos.error("a rule names its reversal date once"));
                }
                if produces != Produces::Adjusting {
                    return Err(pos.error(
                        "only an Adjusting entry schedules its reversal; declare `produces Adjusting`",
                    ));
                }
                reverses = Some(checker.date(date, *pos)?);
            }
        }
    }
    let Checker {
        inputs,
        slots,
        unit_refs,
        ..
    } = checker;
    CompiledRule::seal(Parts {
        name: rule.name,
        version: rule.version,
        event,
        produces,
        inputs,
        slots: slots.into_iter().map(|t| t.node).collect(),
        legs,
        effective: effective.unwrap_or(DateSource::Occurred),
        reverses,
        units: unit_refs,
    })
    .map_err(|e| Pos { line: 1, column: 1 }.error(e.0))
}

#[derive(Clone, Copy, Debug)]
enum Bound {
    Input(u32),
    Slot(u32),
}

/// An amount expression after checking: its IR and unit.
#[derive(Clone, Debug)]
struct Typed {
    node: Node,
    unit: UnitId,
}

struct Checker<'a> {
    units: &'a UnitRegistry,
    inputs: Vec<InputDecl>,
    slots: Vec<Typed>,
    names: BTreeMap<String, Bound>,
    unit_refs: BTreeMap<UnitId, UnitRef>,
}

impl Checker<'_> {
    /// `event.occurred_on`, or a declared date input.
    fn date(&self, date: &DateRef, pos: Pos) -> Result<DateSource, CanonError> {
        match date {
            DateRef::Occurred => Ok(DateSource::Occurred),
            DateRef::Name(name) => match self.names.get(name) {
                Some(Bound::Input(index))
                    if self.inputs[*index as usize].ty == InputType::Date =>
                {
                    Ok(DateSource::Input(*index))
                }
                _ => Err(pos.error(format!(
                    "`{name}` is not a declared date input; declare it as `inputs {{ {name}: date }}`"
                ))),
            },
        }
    }

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
        self.unit_refs.insert(
            id,
            UnitRef {
                code: unit.code.clone(),
                version: unit.version,
                scale: unit.scale,
            },
        );
        Ok(id)
    }

    fn spelling(&self, unit: UnitId) -> String {
        self.unit_refs
            .get(&unit)
            .map_or_else(|| format!("#{}", unit.0), UnitRef::spelling)
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
                })
            }
            Expr::Name(name, pos) => match self.names.get(name).copied() {
                Some(Bound::Slot(index)) => Ok(Typed {
                    node: Node::Slot(index),
                    unit: self.slots[index as usize].unit,
                }),
                Some(Bound::Input(index)) => match self.inputs[index as usize].ty {
                    InputType::Amount(unit) => Ok(Typed {
                        node: Node::Input(index),
                        unit,
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
                Ok(Typed {
                    node: Node::Resource {
                        label: label.clone(),
                        unit,
                    },
                    unit,
                })
            }
            Expr::Add(left, right) | Expr::Sub(left, right) => {
                let add = matches!(expr, Expr::Add(..));
                let l = self.amount(left)?;
                let r = self.amount(right)?;
                if l.unit != r.unit {
                    return Err(expr_pos(right).error(format!(
                        "a {} amount cannot be {} a {} amount; units convert only under a named FX law",
                        self.spelling(r.unit),
                        if add { "added to" } else { "subtracted from" },
                        self.spelling(l.unit),
                    )));
                }
                let (a, b) = (Box::new(l.node), Box::new(r.node));
                Ok(Typed {
                    node: if add { Node::Add(a, b) } else { Node::Sub(a, b) },
                    unit: l.unit,
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
                let (num, den) = reduce(num, den);
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
                // A ratio that reduces to a whole number is exact: it needs
                // no law, and 1/1 is no scale at all.
                let node = match (num, den) {
                    (1, 1) => inner.node,
                    (_, 1) => Node::Scale {
                        operand: Box::new(inner.node),
                        num,
                        den,
                        law: None,
                    },
                    _ => Node::Scale {
                        operand: Box::new(inner.node),
                        num,
                        den,
                        law,
                    },
                };
                Ok(Typed {
                    node,
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
