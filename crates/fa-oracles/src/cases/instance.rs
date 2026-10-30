//! A std-only reader of the XBRL 2.1 instance `fa export xbrl` writes, and
//! X-T-02's comparison of it with a filer's tagged value
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §10.1; bead fa-yugf.49, X4).
//!
//! fa-oracles stays engine-independent: this is its own reading of the
//! exported file, never fa-formats' reader. It reads each context (its id,
//! its instant or duration, and whether an `xbrli:segment` or
//! `xbrli:scenario` makes it dimensional), each unit's measure, and each
//! fact element under the root: its QName as written, `contextRef`,
//! `unitRef`, `decimals` and value. A malformed document is an error, never
//! a partial read, and so is one concept reported twice in one context and
//! unit with different values.

use std::collections::BTreeMap;
use std::fmt;

/// A context's period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Period {
    Instant(String),
    Duration { start: String, end: String },
}

/// One `xbrli:context`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub id: String,
    pub period: Period,
    /// It carries an `xbrli:segment` or `xbrli:scenario`.
    pub dimensional: bool,
}

/// One fact element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    /// The element's QName as written (`us-gaap:Assets`).
    pub concept: String,
    pub context: String,
    pub unit: Option<String>,
    pub decimals: Option<String>,
    pub value: String,
}

/// A read instance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Instance {
    pub contexts: BTreeMap<String, Context>,
    /// Unit id → its measure (`iso4217:USD`).
    pub units: BTreeMap<String, String>,
    pub facts: Vec<Fact>,
}

/// Why an instance does not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstanceError {
    /// Not well-formed, or not an `xbrli:xbrl` document.
    Malformed(String),
    /// A fact names a context the instance does not define.
    MissingContext { concept: String, context: String },
    /// One concept, context and unit with two different values.
    ConflictingFact {
        concept: String,
        context: String,
        first: String,
        second: String,
    },
}

impl fmt::Display for InstanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed instance: {why}"),
            Self::MissingContext { concept, context } => {
                write!(
                    f,
                    "fact {concept} names context `{context}`, which is not defined"
                )
            }
            Self::ConflictingFact {
                concept,
                context,
                first,
                second,
            } => write!(
                f,
                "fact {concept} in context `{context}` is reported twice with different values: {first} and {second}"
            ),
        }
    }
}

/// One markup event.
enum Event {
    Open(String, Vec<(String, String)>),
    Close(String),
    Text(String),
}

fn local(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, l)| l)
}

fn unescape(text: &str) -> Result<String, InstanceError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let end = rest[at..]
            .find(';')
            .ok_or_else(|| InstanceError::Malformed(format!("unterminated entity in `{text}`")))?;
        let entity = &rest[at + 1..at + end];
        let ch = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(dec) = entity.strip_prefix('#') {
                    dec.parse().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32).ok_or_else(|| {
                    InstanceError::Malformed(format!("unknown entity `&{entity};`"))
                })?
            }
        };
        out.push(ch);
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn attributes(body: &str) -> Result<Vec<(String, String)>, InstanceError> {
    let mut out = Vec::new();
    let mut rest = body.trim_start();
    while !rest.is_empty() {
        let eq = rest.find('=').ok_or_else(|| {
            InstanceError::Malformed(format!("attribute without a value in `{body}`"))
        })?;
        let name = rest[..eq].trim().to_string();
        let after = rest[eq + 1..].trim_start();
        let quote = after
            .chars()
            .next()
            .filter(|c| *c == '"' || *c == '\'')
            .ok_or_else(|| InstanceError::Malformed(format!("unquoted attribute `{name}`")))?;
        let close = after[1..]
            .find(quote)
            .ok_or_else(|| InstanceError::Malformed(format!("unterminated attribute `{name}`")))?;
        out.push((name, unescape(&after[1..=close])?));
        rest = after[close + 2..].trim_start();
    }
    Ok(out)
}

/// The document's markup events; an unterminated construct is an error.
fn events(xml: &str) -> Result<Vec<Event>, InstanceError> {
    let mut out = Vec::new();
    let mut rest = xml;
    while !rest.is_empty() {
        let Some(at) = rest.find('<') else {
            out.push(Event::Text(unescape(rest)?));
            break;
        };
        if at > 0 {
            out.push(Event::Text(unescape(&rest[..at])?));
        }
        rest = &rest[at..];
        let skip = |open: &str, close: &str, rest: &str| -> Result<usize, InstanceError> {
            rest.find(close)
                .map(|e| e + close.len())
                .ok_or_else(|| InstanceError::Malformed(format!("unterminated `{open}`")))
        };
        if rest.starts_with("<?") {
            rest = &rest[skip("<?", "?>", rest)?..];
            continue;
        }
        if rest.starts_with("<!--") {
            rest = &rest[skip("<!--", "-->", rest)?..];
            continue;
        }
        if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
            let end = cdata
                .find("]]>")
                .ok_or_else(|| InstanceError::Malformed("unterminated CDATA section".into()))?;
            out.push(Event::Text(cdata[..end].to_string()));
            rest = &cdata[end + 3..];
            continue;
        }
        if rest.starts_with("<!") {
            rest = &rest[skip("<!", ">", rest)?..];
            continue;
        }
        let end = rest
            .find('>')
            .ok_or_else(|| InstanceError::Malformed("unterminated tag".into()))?;
        let tag = &rest[1..end];
        rest = &rest[end + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            out.push(Event::Close(name.trim().to_string()));
            continue;
        }
        let (body, empty) = match tag.strip_suffix('/') {
            Some(body) => (body, true),
            None => (tag, false),
        };
        let split = body.find(|c: char| c.is_whitespace()).unwrap_or(body.len());
        let name = body[..split].to_string();
        if name.is_empty() {
            return Err(InstanceError::Malformed("a tag without a name".into()));
        }
        out.push(Event::Open(name.clone(), attributes(&body[split..])?));
        if empty {
            out.push(Event::Close(name));
        }
    }
    Ok(out)
}

/// The partial context a reader builds while inside `xbrli:context`.
#[derive(Default)]
struct Building {
    id: String,
    instant: Option<String>,
    start: Option<String>,
    end: Option<String>,
    dimensional: bool,
}

/// Reads an instance document.
///
/// # Errors
///
/// [`InstanceError`]: the document is malformed, a fact names an undefined
/// context, or one concept, context and unit carries two different values.
pub fn read(xml: &str) -> Result<Instance, InstanceError> {
    let mut stack: Vec<String> = Vec::new();
    let mut inst = Instance::default();
    let mut context: Option<Building> = None;
    let mut unit: Option<(String, String)> = None;
    let mut fact: Option<Fact> = None;
    let mut text = String::new();
    let mut root_seen = false;
    for event in events(xml)? {
        match event {
            Event::Open(name, attrs) => {
                let attr = |key: &str| attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
                if stack.is_empty() {
                    if root_seen || local(&name) != "xbrl" {
                        return Err(InstanceError::Malformed(format!(
                            "the document element is `{name}`, not one xbrli:xbrl"
                        )));
                    }
                    root_seen = true;
                } else if stack.len() == 1 {
                    match local(&name) {
                        "context" => {
                            context = Some(Building {
                                id: attr("id").unwrap_or_default(),
                                ..Building::default()
                            });
                        }
                        "unit" => unit = Some((attr("id").unwrap_or_default(), String::new())),
                        _ => {
                            if let Some(context) = attr("contextRef") {
                                fact = Some(Fact {
                                    concept: name.clone(),
                                    context,
                                    unit: attr("unitRef"),
                                    decimals: attr("decimals"),
                                    value: String::new(),
                                });
                            }
                        }
                    }
                } else if let Some(c) = context.as_mut()
                    && matches!(local(&name), "segment" | "scenario")
                {
                    c.dimensional = true;
                }
                text.clear();
                stack.push(name);
            }
            Event::Close(name) => {
                let open = stack.pop().ok_or_else(|| {
                    InstanceError::Malformed(format!("`</{name}>` closes nothing"))
                })?;
                if open != name {
                    return Err(InstanceError::Malformed(format!(
                        "`<{open}>` is closed by `</{name}>`"
                    )));
                }
                let value = text.trim().to_string();
                if let Some(c) = context.as_mut() {
                    match local(&name) {
                        "instant" => c.instant = Some(value.clone()),
                        "startDate" => c.start = Some(value.clone()),
                        "endDate" => c.end = Some(value.clone()),
                        _ => {}
                    }
                }
                if let Some((_, measure)) = unit.as_mut()
                    && local(&name) == "measure"
                {
                    *measure = value.clone();
                }
                if stack.len() == 1 {
                    match local(&name) {
                        "context" => {
                            let Some(c) = context.take() else { continue };
                            let period = match (c.instant, c.start, c.end) {
                                (Some(instant), None, None) => Period::Instant(instant),
                                (None, Some(start), Some(end)) => Period::Duration { start, end },
                                _ => {
                                    return Err(InstanceError::Malformed(format!(
                                        "context `{}` has neither one instant nor a start and an end date",
                                        c.id
                                    )));
                                }
                            };
                            inst.contexts.insert(
                                c.id.clone(),
                                Context {
                                    id: c.id,
                                    period,
                                    dimensional: c.dimensional,
                                },
                            );
                        }
                        "unit" => {
                            if let Some((id, measure)) = unit.take() {
                                inst.units.insert(id, measure);
                            }
                        }
                        _ => {
                            if let Some(mut f) = fact.take() {
                                f.value = value;
                                inst.facts.push(f);
                            }
                        }
                    }
                }
                text.clear();
            }
            Event::Text(t) => {
                if stack.is_empty() && !t.trim().is_empty() {
                    return Err(InstanceError::Malformed(
                        "text outside the document element".into(),
                    ));
                }
                text.push_str(&t);
            }
        }
    }
    if let Some(open) = stack.last() {
        return Err(InstanceError::Malformed(format!(
            "`<{open}>` is never closed"
        )));
    }
    if !root_seen {
        return Err(InstanceError::Malformed("no document element".into()));
    }
    let mut seen: BTreeMap<(&str, &str, Option<&str>), &str> = BTreeMap::new();
    for f in &inst.facts {
        if !inst.contexts.contains_key(&f.context) {
            return Err(InstanceError::MissingContext {
                concept: f.concept.clone(),
                context: f.context.clone(),
            });
        }
        let key = (f.concept.as_str(), f.context.as_str(), f.unit.as_deref());
        match seen.get(&key) {
            Some(first) if *first != f.value => {
                return Err(InstanceError::ConflictingFact {
                    concept: f.concept.clone(),
                    context: f.context.clone(),
                    first: (*first).to_string(),
                    second: f.value.clone(),
                });
            }
            _ => {
                seen.insert(key, f.value.as_str());
            }
        }
    }
    Ok(inst)
}

/// A fact's decimal value in minor units at `scale`: refused when it has
/// more nonzero places than the scale holds.
///
/// # Errors
///
/// Why the value is not an exact amount at `scale`.
pub fn minor_units(value: &str, scale: u8) -> Result<i128, String> {
    let (negative, body) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let (whole, frac) = body.split_once('.').unwrap_or((body, ""));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || !(frac.is_empty() || digits(frac)) {
        return Err(format!("`{value}` is not a decimal number"));
    }
    let places = usize::from(scale);
    let (kept, dropped) = frac.split_at(frac.len().min(places));
    if dropped.bytes().any(|b| b != b'0') {
        return Err(format!(
            "`{value}` has more places than the unit's scale {scale}"
        ));
    }
    let mut text = format!("{whole}{kept}");
    text.extend(std::iter::repeat_n('0', places - kept.len()));
    let magnitude: i128 = text
        .parse()
        .map_err(|_| format!("`{value}` overflows an exact amount"))?;
    Ok(if negative { -magnitude } else { magnitude })
}

/// X-T-02's comparison: the exported value ([`instant_value`]) must equal
/// `published` exactly. `Ok` carries the exported value; `Err` names the
/// concept, the instant and both values, or why there is no value (a
/// renamed QName matches nothing else).
///
/// # Errors
///
/// The fact is missing, ambiguous, not an exact amount, or unequal.
pub fn compare(
    inst: &Instance,
    concept: &str,
    date: &str,
    unit: &str,
    scale: u8,
    published: i128,
) -> Result<i128, String> {
    let exported = instant_value(inst, concept, date, unit, scale)?;
    if exported == published {
        Ok(exported)
    } else {
        Err(format!(
            "expected {concept} at {date} = {published} observed {exported} (minor units at scale {scale})"
        ))
    }
}

/// The non-dimensional instant fact of `concept` at `date` whose unit's
/// measure is `unit` (`iso4217:<unit>`), read in minor units at `scale`.
/// The same value reported in two such contexts is one value; two
/// different ones are no value.
///
/// # Errors
///
/// No such fact, two different values, or a value that is not an exact
/// amount at `scale`.
pub fn instant_value(
    inst: &Instance,
    concept: &str,
    date: &str,
    unit: &str,
    scale: u8,
) -> Result<i128, String> {
    let measure = format!("iso4217:{unit}");
    let mut found: Vec<(&Fact, i128)> = Vec::new();
    for f in inst.facts.iter().filter(|f| f.concept == concept) {
        let Some(c) = inst.contexts.get(&f.context) else {
            continue;
        };
        let instant = matches!(&c.period, Period::Instant(d) if d == date);
        let in_unit = f
            .unit
            .as_ref()
            .and_then(|u| inst.units.get(u))
            .is_some_and(|m| *m == measure);
        if instant && !c.dimensional && in_unit {
            found.push((f, minor_units(&f.value, scale)?));
        }
    }
    match found.as_slice() {
        [] => Err(format!(
            "expected a non-dimensional instant fact {concept} at {date} in {unit} observed none"
        )),
        [(_, v), rest @ ..] if rest.iter().all(|(_, w)| w == v) => Ok(*v),
        _ => Err(format!(
            "expected one value of {concept} at {date} in {unit} observed {}",
            found
                .iter()
                .map(|(f, _)| format!("{}={}", f.context, f.value))
                .collect::<Vec<_>>()
                .join(",")
        )),
    }
}
