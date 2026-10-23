//! The typed IR a rule compiles to, its canonical bytes and its content
//! address. Lets are numbered slots, so renaming one, or reformatting the
//! source, leaves the address unchanged; every unit is spelled with its code,
//! version and scale, so the address does not depend on one book's unit ids.
//!
//! [`CompiledRule::seal`] is the one way to make a rule: it validates the
//! IR's structure, re-runs the balance proof over the IR and derives the
//! dependency set from it. [`CompiledRule::decode`] reads canonical bytes
//! back (a journaled rule version) through the same gate and refuses bytes
//! that are not exactly what the IR encodes to, so a stored rule is never
//! trusted for what it claims to be.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::proof::{self, Unproven};
use fa_model::{
    DecodeError, EncodeError, EventKind, Reader, Writer, dimension_kind, domain_digest,
};
use fa_money::{RoundingLaw, Side, UnitId, UnitRegistry};

/// `rule_version_oid = BLAKE3("fa:canon-ir:v1" ‖ len(ir) ‖ ir)`.
pub const CANON_IR_DOMAIN: &[u8] = b"fa:canon-ir:v1";
/// `inputs_digest = BLAKE3("fa:canon-inputs:v1" ‖ len(inputs) ‖ inputs)`.
pub const CANON_INPUTS_DOMAIN: &[u8] = b"fa:canon-inputs:v1";

/// Bounds on what a decoded IR may hold; a compiled rule is within them
/// by the parser's own bounds.
const MAX_NODE_DEPTH: u32 = 256;
const MAX_SLOTS: usize = 512;
const MAX_LEGS: usize = 512;
const MAX_INPUTS: usize = 64;
const MAX_DIMS: usize = 16;
const MAX_TEXT: usize = 1024;

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
    /// `operand × num ÷ den`, with `num/den` in lowest terms and not 1/1.
    /// `law` is `None` exactly when `den == 1`, so the product is exact.
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

/// An IR the gate refuses: structurally invalid, not proven balanced, or
/// (decoded) not canonical or naming a unit this book does not hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrError(pub String);

impl fmt::Display for IrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for IrError {}

impl From<DecodeError> for IrError {
    fn from(e: DecodeError) -> Self {
        Self(format!("the IR bytes do not decode: {e}"))
    }
}

/// A rule before it is sealed: the IR alone.
pub(crate) struct Parts {
    pub name: String,
    pub version: u32,
    pub event: EventKind,
    pub inputs: Vec<InputDecl>,
    pub slots: Vec<Node>,
    pub legs: Vec<LegTemplate>,
    pub effective: DateSource,
    pub units: BTreeMap<UnitId, UnitRef>,
}

/// A checked rule: the typed IR, its canonical bytes and content address,
/// and its dependency set. Only [`CompiledRule::seal`] builds one, so the
/// bytes, the address and the proof always describe the IR beside them.
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

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while let Some(r) = a.checked_rem(b) {
        a = b;
        b = r;
    }
    a
}

pub(crate) fn reduce(num: u128, den: u128) -> (u128, u128) {
    let divisor = gcd(num, den);
    (
        num.checked_div(divisor).unwrap_or(num),
        den.checked_div(divisor).unwrap_or(den),
    )
}

/// The unit of `node`, checking it is well formed on the way.
fn node_unit(
    node: &Node,
    parts: &Parts,
    slot_units: &[UnitId],
    depth: u32,
) -> Result<UnitId, IrError> {
    if depth > MAX_NODE_DEPTH {
        return Err(IrError(format!(
            "an expression nests deeper than {MAX_NODE_DEPTH}"
        )));
    }
    let known = |unit: &UnitId| {
        if parts.units.contains_key(unit) {
            Ok(*unit)
        } else {
            Err(IrError(format!(
                "unit #{} is not in the rule's unit table",
                unit.0
            )))
        }
    };
    match node {
        Node::Literal { unit, .. } => known(unit),
        Node::Resource { label, unit } => {
            if label.is_empty() {
                return Err(IrError("a resource label is empty".into()));
            }
            known(unit)
        }
        Node::Input(index) => match parts.inputs.get(*index as usize).map(|i| &i.ty) {
            Some(InputType::Amount(unit)) => known(unit),
            _ => Err(IrError(format!(
                "input #{index} is not a declared amount input"
            ))),
        },
        Node::Slot(index) => slot_units
            .get(*index as usize)
            .copied()
            .ok_or_else(|| IrError(format!("let #{index} is not an earlier let"))),
        Node::Add(left, right) | Node::Sub(left, right) => {
            let next = depth.saturating_add(1);
            let l = node_unit(left, parts, slot_units, next)?;
            let r = node_unit(right, parts, slot_units, next)?;
            if l == r {
                Ok(l)
            } else {
                Err(IrError("an addition or subtraction mixes units".into()))
            }
        }
        Node::Scale {
            operand,
            num,
            den,
            law,
        } => {
            if *num == 0
                || *den == 0
                || reduce(*num, *den) != (*num, *den)
                || (*num, *den) == (1, 1)
            {
                return Err(IrError(format!(
                    "a scale {num}/{den} is not a nonzero ratio in lowest terms"
                )));
            }
            if law.is_none() != (*den == 1) {
                return Err(IrError(
                    "a scale names a rounding law exactly when it divides".into(),
                ));
            }
            node_unit(operand, parts, slot_units, depth.saturating_add(1))
        }
    }
}

fn well_formed_code(text: &str) -> bool {
    !text.is_empty() && text.trim() == text
}

/// The structural law every IR obeys, compiled or decoded.
fn validate(parts: &Parts) -> Result<(), IrError> {
    if parts.name.is_empty() || parts.version == 0 {
        return Err(IrError(
            "a rule has a name and a version of at least 1".into(),
        ));
    }
    let mut names = BTreeSet::new();
    for input in &parts.inputs {
        if input.name.is_empty() || !names.insert(input.name.as_str()) {
            return Err(IrError(format!(
                "input `{}` is empty or declared twice",
                input.name
            )));
        }
        if let InputType::Amount(unit) = &input.ty
            && !parts.units.contains_key(unit)
        {
            return Err(IrError(format!(
                "input `{}` names an unknown unit",
                input.name
            )));
        }
    }
    let mut slot_units = Vec::with_capacity(parts.slots.len());
    for node in &parts.slots {
        slot_units.push(node_unit(node, parts, &slot_units, 0)?);
    }
    if !parts.legs.iter().any(|l| l.side == Side::Debit)
        || !parts.legs.iter().any(|l| l.side == Side::Credit)
    {
        return Err(IrError(
            "a rule derives at least one debit and one credit".into(),
        ));
    }
    for leg in &parts.legs {
        if !well_formed_code(&leg.account) {
            return Err(IrError(
                "a leg names its account code without spaces around it".into(),
            ));
        }
        if node_unit(&leg.amount, parts, &slot_units, 0)? != leg.unit {
            return Err(IrError(format!(
                "the leg on {} is not in its declared unit",
                leg.account
            )));
        }
        let mut last = None;
        for (dimension, code) in &leg.dims {
            let Some(kind) = dimension_kind(dimension) else {
                return Err(IrError(format!(
                    "`{dimension}` is not a registered dimension"
                )));
            };
            if !well_formed_code(code) {
                return Err(IrError(format!("the {dimension} tag names no value code")));
            }
            if last.is_some_and(|id| id >= kind.id) {
                return Err(IrError(
                    "a leg's dimension tags are not unique and ascending by dimension".into(),
                ));
            }
            last = Some(kind.id);
        }
    }
    if let DateSource::Input(index) = parts.effective
        && parts.inputs.get(index as usize).map(|i| &i.ty) != Some(&InputType::Date)
    {
        return Err(IrError(format!(
            "input #{index} is not a declared date input"
        )));
    }
    Ok(())
}

fn collect(node: &Node, parts: &Parts, deps: &mut Dependencies) {
    match node {
        Node::Literal { .. } | Node::Input(_) | Node::Slot(_) => {}
        Node::Resource { label, unit } => {
            if let Some(unit) = parts.units.get(unit) {
                deps.resources.insert((label.clone(), unit.spelling()));
            }
        }
        Node::Add(left, right) | Node::Sub(left, right) => {
            collect(left, parts, deps);
            collect(right, parts, deps);
        }
        Node::Scale { operand, law, .. } => {
            if let Some(law) = law {
                deps.laws.insert(law.name().to_string());
            }
            collect(operand, parts, deps);
        }
    }
}

fn dependencies(parts: &Parts) -> Dependencies {
    let mut deps = Dependencies {
        units: parts.units.values().map(UnitRef::spelling).collect(),
        ..Dependencies::default()
    };
    for node in &parts.slots {
        collect(node, parts, &mut deps);
    }
    for leg in &parts.legs {
        deps.accounts.insert(leg.account.clone());
        deps.dimensions.extend(leg.dims.iter().cloned());
        collect(&leg.amount, parts, &mut deps);
    }
    deps
}

impl CompiledRule {
    /// Validate, prove and encode `parts`: the one constructor.
    pub(crate) fn seal(parts: Parts) -> Result<Self, IrError> {
        validate(&parts)?;
        match proof::prove(&parts) {
            Ok(()) => {}
            Err(Unproven::Unbalanced { unit, residual }) => {
                return Err(IrError(format!(
                    "the rule does not balance in {unit}: debits minus credits is {residual}; every rule proves its debits equal its credits per unit, and Canon never adds a residual leg"
                )));
            }
            Err(Unproven::Overflow) => {
                return Err(IrError(
                    "the rule's balance coefficients leave the i128 range".into(),
                ));
            }
        }
        let dependencies = dependencies(&parts);
        let ir = encode(&parts).map_err(|e| IrError(format!("the IR does not encode: {e}")))?;
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

    /// Read canonical `fa:canon-ir:v1` bytes against this book's units,
    /// through the same validation and balance proof as a compiled rule.
    /// Bytes that are not exactly the encoding of what they decode to are
    /// refused, so a stored version's address is the digest of what runs.
    pub fn decode(ir: &[u8], units: &UnitRegistry) -> Result<Self, IrError> {
        let rule = Self::seal(read(ir, units)?)?;
        if rule.ir != ir {
            return Err(IrError(
                "the IR bytes are not canonical: they do not re-encode to themselves".into(),
            ));
        }
        Ok(rule)
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

/// Reads a unit reference and resolves it to exactly that unit version in
/// `registry`, at the scale the IR spells.
fn read_unit(
    r: &mut Reader<'_>,
    registry: &UnitRegistry,
    units: &mut BTreeMap<UnitId, UnitRef>,
) -> Result<UnitId, IrError> {
    let unit = UnitRef {
        code: r.str(64, "rule.unit.code")?.to_string(),
        version: r.u16("rule.unit.version")?,
        scale: r.u8("rule.unit.scale")?,
    };
    let id = registry
        .lookup(&format!("{}@v{}", unit.code, unit.version))
        .ok_or_else(|| {
            IrError(format!(
                "unit {} is not registered in this book",
                unit.spelling()
            ))
        })?;
    if registry.get(id).map(|u| u.scale) != Some(unit.scale) {
        return Err(IrError(format!(
            "unit {} has another scale in this book than the rule spells",
            unit.spelling()
        )));
    }
    units.insert(id, unit);
    Ok(id)
}

fn read_node(
    r: &mut Reader<'_>,
    registry: &UnitRegistry,
    units: &mut BTreeMap<UnitId, UnitRef>,
    depth: u32,
) -> Result<Node, IrError> {
    if depth > MAX_NODE_DEPTH {
        return Err(IrError(format!(
            "an expression nests deeper than {MAX_NODE_DEPTH}"
        )));
    }
    let next = depth.saturating_add(1);
    Ok(match r.u8("rule.node")? {
        1 => {
            let unit = read_unit(r, registry, units)?;
            Node::Literal {
                unit,
                mantissa: r.i128("rule.node.mantissa")?,
            }
        }
        2 => {
            let label = r.str(MAX_TEXT, "rule.node.label")?.to_string();
            Node::Resource {
                label,
                unit: read_unit(r, registry, units)?,
            }
        }
        3 => Node::Input(r.u32("rule.node.input")?),
        4 => Node::Slot(r.u32("rule.node.slot")?),
        tag @ (5 | 6) => {
            let left = Box::new(read_node(r, registry, units, next)?);
            let right = Box::new(read_node(r, registry, units, next)?);
            if tag == 5 {
                Node::Add(left, right)
            } else {
                Node::Sub(left, right)
            }
        }
        7 => {
            let operand = Box::new(read_node(r, registry, units, next)?);
            let num = r.u128("rule.node.num")?;
            let den = r.u128("rule.node.den")?;
            let law = match r.u16("rule.node.law")? {
                0 => None,
                id => Some(
                    RoundingLaw::from_id(id)
                        .ok_or_else(|| IrError(format!("rounding law #{id} is not registered")))?,
                ),
            };
            Node::Scale {
                operand,
                num,
                den,
                law,
            }
        }
        tag => return Err(r.bad_tag("rule.node", tag).into()),
    })
}

fn read(ir: &[u8], registry: &UnitRegistry) -> Result<Parts, IrError> {
    let mut r = Reader::new(ir);
    let mut units = BTreeMap::new();
    let name = r.str(MAX_TEXT, "rule.name")?.to_string();
    let version = r.u32("rule.version")?;
    let tag = r.u8("rule.event")?;
    let event = EventKind::from_tag(tag).ok_or_else(|| r.bad_tag("rule.event", tag))?;
    let mut inputs = Vec::new();
    for _ in 0..r.count(MAX_INPUTS, "rule.inputs")? {
        let name = r.str(MAX_TEXT, "rule.input.name")?.to_string();
        let ty = match r.u8("rule.input.type")? {
            1 => InputType::Date,
            2 => InputType::Amount(read_unit(&mut r, registry, &mut units)?),
            tag => return Err(r.bad_tag("rule.input.type", tag).into()),
        };
        inputs.push(InputDecl { name, ty });
    }
    let mut slots = Vec::new();
    for _ in 0..r.count(MAX_SLOTS, "rule.slots")? {
        slots.push(read_node(&mut r, registry, &mut units, 0)?);
    }
    let mut raw_legs = Vec::new();
    for _ in 0..r.count(MAX_LEGS, "rule.legs")? {
        let side = match r.u8("rule.leg.side")? {
            1 => Side::Debit,
            2 => Side::Credit,
            tag => return Err(r.bad_tag("rule.leg.side", tag).into()),
        };
        let account = r.str(MAX_TEXT, "rule.leg.account")?.to_string();
        let amount = read_node(&mut r, registry, &mut units, 0)?;
        let mut dims = Vec::new();
        for _ in 0..r.count(MAX_DIMS, "rule.leg.dims")? {
            let dimension = r.str(MAX_TEXT, "rule.leg.dimension")?.to_string();
            let code = r.str(MAX_TEXT, "rule.leg.dimension_code")?.to_string();
            dims.push((dimension, code));
        }
        raw_legs.push((side, account, amount, dims));
    }
    let effective = match r.u8("rule.effective")? {
        0 => DateSource::Occurred,
        1 => DateSource::Input(r.u32("rule.effective.input")?),
        tag => return Err(r.bad_tag("rule.effective", tag).into()),
    };
    r.finish()?;
    let mut parts = Parts {
        name,
        version,
        event,
        inputs,
        slots,
        legs: Vec::new(),
        effective,
        units,
    };
    // A leg's unit is its amount's; validation re-checks it.
    let mut slot_units = Vec::with_capacity(parts.slots.len());
    for node in &parts.slots {
        slot_units.push(node_unit(node, &parts, &slot_units, 0)?);
    }
    for (side, account, amount, dims) in raw_legs {
        let unit = node_unit(&amount, &parts, &slot_units, 0)?;
        parts.legs.push(LegTemplate {
            side,
            account,
            unit,
            amount,
            dims,
        });
    }
    Ok(parts)
}
