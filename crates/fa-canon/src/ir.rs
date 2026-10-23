//! The typed IR a rule compiles to, its canonical bytes and its content
//! address. Lets are numbered slots, so renaming one, or reformatting the
//! source, leaves the address unchanged; every unit is spelled with its code,
//! version and scale, so the address does not depend on one book's unit ids.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{EncodeError, EventKind, Writer, domain_digest};
use fa_money::{RoundingLaw, Side, UnitId};

/// `rule_version_oid = BLAKE3("fa:canon-ir:v1" ‖ len(ir) ‖ ir)`.
pub const CANON_IR_DOMAIN: &[u8] = b"fa:canon-ir:v1";
/// `inputs_digest = BLAKE3("fa:canon-inputs:v1" ‖ len(inputs) ‖ inputs)`.
pub const CANON_INPUTS_DOMAIN: &[u8] = b"fa:canon-inputs:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputType {
    Date,
    Amount(UnitId),
}

/// One declared input: the only way a value outside the event, such as
/// "today" or a fee, reaches a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputDecl {
    pub name: String,
    pub ty: InputType,
}

/// An amount expression. Every node has one unit, fixed by the checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Literal {
        unit: UnitId,
        mantissa: i128,
    },
    Resource {
        label: String,
        unit: UnitId,
    },
    /// A declared amount input, by its index in [`CompiledRule::inputs`].
    Input(u32),
    /// An earlier let, by its index in [`CompiledRule::slots`].
    Slot(u32),
    Add(Box<Node>, Box<Node>),
    Sub(Box<Node>, Box<Node>),
    /// `operand × num ÷ den`, with `num/den` in lowest terms. `law` is
    /// `None` exactly when `den == 1`, so the product is exact.
    Scale {
        operand: Box<Node>,
        num: u128,
        den: u128,
        law: Option<RoundingLaw>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateSource {
    Occurred,
    /// A declared date input, by its index in [`CompiledRule::inputs`].
    Input(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegTemplate {
    pub side: Side,
    pub account: String,
    pub unit: UnitId,
    pub amount: Node,
    /// `(dimension code, value code)`, ascending by the dimension's id.
    pub dims: Vec<(String, String)>,
}

/// What a rule may reference: the static dependency set (plan §10.3) a chart
/// or registry change is checked against.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dependencies {
    pub accounts: BTreeSet<String>,
    pub units: BTreeSet<String>,
    pub laws: BTreeSet<String>,
    /// `(label, unit)` event resources the rule reads.
    pub resources: BTreeSet<(String, String)>,
    /// `(dimension, value code)` tags the rule writes.
    pub dimensions: BTreeSet<(String, String)>,
}

/// A unit as the IR spells it: independent of any one registry's ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnitRef {
    pub code: String,
    pub version: u16,
    pub scale: u8,
}

impl UnitRef {
    pub(crate) fn spelling(&self) -> String {
        if self.version == 0 {
            self.code.clone()
        } else {
            format!("{}@v{}", self.code, self.version)
        }
    }
}

/// A checked rule: the typed IR, its canonical bytes and content address,
/// and its dependency set. Only [`crate::compile`] builds one, so the bytes
/// and address always describe the IR beside them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRule {
    name: String,
    version: u32,
    event: EventKind,
    inputs: Vec<InputDecl>,
    slots: Vec<Node>,
    legs: Vec<LegTemplate>,
    effective: DateSource,
    units: BTreeMap<UnitId, UnitRef>,
    dependencies: Dependencies,
    ir: Vec<u8>,
    ir_digest: [u8; 32],
}

pub(crate) struct Parts {
    pub name: String,
    pub version: u32,
    pub event: EventKind,
    pub inputs: Vec<InputDecl>,
    pub slots: Vec<Node>,
    pub legs: Vec<LegTemplate>,
    pub effective: DateSource,
    pub units: BTreeMap<UnitId, UnitRef>,
    pub dependencies: Dependencies,
}

impl CompiledRule {
    pub(crate) fn seal(parts: Parts) -> Result<Self, EncodeError> {
        let ir = encode(&parts)?;
        let ir_digest = domain_digest(CANON_IR_DOMAIN, &[&ir]);
        let Parts {
            name,
            version,
            event,
            inputs,
            slots,
            legs,
            effective,
            units,
            dependencies,
        } = parts;
        Ok(Self {
            name,
            version,
            event,
            inputs,
            slots,
            legs,
            effective,
            units,
            dependencies,
            ir,
            ir_digest,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub fn event(&self) -> EventKind {
        self.event
    }

    #[must_use]
    pub fn inputs(&self) -> &[InputDecl] {
        &self.inputs
    }

    #[must_use]
    pub fn slots(&self) -> &[Node] {
        &self.slots
    }

    #[must_use]
    pub fn legs(&self) -> &[LegTemplate] {
        &self.legs
    }

    #[must_use]
    pub fn effective(&self) -> DateSource {
        self.effective
    }

    #[must_use]
    pub fn dependencies(&self) -> &Dependencies {
        &self.dependencies
    }

    /// The canonical `fa:canon-ir:v1` bytes.
    #[must_use]
    pub fn ir(&self) -> &[u8] {
        &self.ir
    }

    /// The content address a `RuleVersion` journals and a rule-derived
    /// entry's origin names.
    #[must_use]
    pub fn ir_digest(&self) -> [u8; 32] {
        self.ir_digest
    }

    pub(crate) fn unit(&self, id: UnitId) -> &UnitRef {
        &self.units[&id]
    }
}

fn side_tag(side: Side) -> u8 {
    match side {
        Side::Debit => 1,
        Side::Credit => 2,
    }
}

pub(crate) fn write_unit(w: &mut Writer, unit: &UnitRef) {
    w.str(&unit.code).u16(unit.version).u8(unit.scale);
}

fn write_node(w: &mut Writer, node: &Node, units: &BTreeMap<UnitId, UnitRef>) {
    match node {
        Node::Literal { unit, mantissa } => {
            w.u8(1);
            write_unit(w, &units[unit]);
            w.i128(*mantissa);
        }
        Node::Resource { label, unit } => {
            w.u8(2).str(label);
            write_unit(w, &units[unit]);
        }
        Node::Input(index) => {
            w.u8(3).u32(*index);
        }
        Node::Slot(index) => {
            w.u8(4).u32(*index);
        }
        Node::Add(left, right) | Node::Sub(left, right) => {
            w.u8(if matches!(node, Node::Add(..)) { 5 } else { 6 });
            write_node(w, left, units);
            write_node(w, right, units);
        }
        Node::Scale {
            operand,
            num,
            den,
            law,
        } => {
            w.u8(7);
            write_node(w, operand, units);
            w.u128(*num).u128(*den).u16(law.map_or(0, RoundingLaw::id));
        }
    }
}

fn encode(parts: &Parts) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::new();
    w.str(&parts.name).u32(parts.version).u8(parts.event.tag());
    w.list(&parts.inputs, |w, input| {
        w.str(&input.name);
        match &input.ty {
            InputType::Date => {
                w.u8(1);
            }
            InputType::Amount(unit) => {
                w.u8(2);
                write_unit(w, &parts.units[unit]);
            }
        }
    });
    w.list(&parts.slots, |w, node| write_node(w, node, &parts.units));
    w.list(&parts.legs, |w, leg| {
        w.u8(side_tag(leg.side)).str(&leg.account);
        write_node(w, &leg.amount, &parts.units);
        w.list(&leg.dims, |w, (dimension, code)| {
            w.str(dimension).str(code);
        });
    });
    match parts.effective {
        DateSource::Occurred => {
            w.u8(0);
        }
        DateSource::Input(index) => {
            w.u8(1).u32(index);
        }
    }
    w.finish()
}
