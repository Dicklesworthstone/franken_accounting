//! The verb registry (`registries/verbs.toml`, plan §15.2–§15.3): the one
//! source of the `fa` CLI's verbs, subcommands, aliases, flags, help text,
//! exit codes, and robot-mode event schemas.
//!
//! The binary's dispatch, flag parser, `--help`, `fa capabilities`, and
//! `fa robot-docs schema` all read this registry; nothing about a verb is
//! hand-maintained in a second place. [`Registry::parse`] refuses an
//! inconsistent registry (an alias to a missing verb, an event naming an
//! undeclared shape, a dead event or shape, a flag that is a value flag in
//! one row and a switch in another), and [`Registry::check_line`] checks one
//! robot-mode output line against its event's schema — the parity tests run
//! it over every `--json` line the binary tests produce.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use fa_registry::toml::{self, Table, Value};

use crate::json::{self, Json};

/// The registry as compiled into this build.
pub const SOURCE: &str = include_str!("../../../registries/verbs.toml");

/// The type vocabulary, as `fa robot-docs schema` prints it.
pub const TYPES: &[&str] = &[
    "string", "text", "int", "seq", "bool", "amount", "date", "hex", "object", "any", "<shape>",
    "[T]", "T?",
];

const SCALARS: &[(&str, Scalar)] = &[
    ("string", Scalar::String),
    ("text", Scalar::Text),
    ("int", Scalar::Int),
    ("seq", Scalar::Seq),
    ("bool", Scalar::Bool),
    ("amount", Scalar::Amount),
    ("date", Scalar::Date),
    ("hex", Scalar::Hex),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    String,
    Text,
    Int,
    /// A CommitSeq: an integer in `0..=u64::MAX`.
    Seq,
    Bool,
    /// `"<exact decimal> <unit code>"`, never a JSON number.
    Amount,
    /// A civil date, `YYYY-MM-DD`.
    Date,
    /// Lowercase hexadecimal.
    Hex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    Scalar(Scalar),
    /// An object whose keys are data (e.g. counts by state).
    Object,
    Any,
    /// An object with exactly the named shape's fields.
    Shape(String),
    Array(Box<Type>),
    Nullable(Box<Type>),
}

impl Type {
    pub fn parse(text: &str) -> Result<Self, String> {
        if let Some(inner) = text.strip_suffix('?') {
            let t = Self::parse(inner)?;
            if matches!(t, Self::Nullable(_)) {
                return Err(format!("type `{text}` is doubly nullable"));
            }
            return Ok(Self::Nullable(Box::new(t)));
        }
        if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
            return Ok(Self::Array(Box::new(Self::parse(inner)?)));
        }
        if let Some((_, s)) = SCALARS.iter().find(|(n, _)| *n == text) {
            return Ok(Self::Scalar(*s));
        }
        match text {
            "object" => Ok(Self::Object),
            "any" => Ok(Self::Any),
            name if is_name(name) => Ok(Self::Shape(name.to_string())),
            other => Err(format!("unknown type `{other}`")),
        }
    }

    fn shapes<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Self::Shape(name) => out.push(name),
            Self::Array(t) | Self::Nullable(t) => t.shapes(out),
            Self::Scalar(_) | Self::Object | Self::Any => {}
        }
    }
}

fn is_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') && !s.starts_with('_')
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    /// The type exactly as the registry spells it.
    pub type_text: String,
    pub ty: Type,
}

/// An event's or a shape's schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    pub name: String,
    pub doc: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verb {
    pub name: String,
    pub summary: String,
    pub writes: bool,
    pub subcommands: Vec<String>,
    pub flags: Vec<String>,
    pub switches: Vec<String>,
    pub events: Vec<String>,
    pub exits: Vec<u8>,
    pub usage: Vec<String>,
    pub example: String,
}

impl Verb {
    /// Whether `flag` (a value flag or a switch) belongs to this verb.
    #[must_use]
    pub fn accepts(&self, flag: &str) -> bool {
        self.flags.iter().chain(&self.switches).any(|f| f == flag)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alias {
    pub name: String,
    pub expands: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub discriminator: String,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Global {
    pub flags: Vec<String>,
    pub switches: Vec<String>,
    /// Events emitted outside any one verb (errors, `--version`, triage, help).
    pub events: Vec<String>,
    pub usage: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    pub envelope: Envelope,
    pub global: Global,
    pub verbs: Vec<Verb>,
    pub aliases: Vec<Alias>,
    pub events: Vec<Schema>,
    pub shapes: Vec<Schema>,
}

/// The embedded registry, parsed and validated once.
pub fn registry() -> Result<&'static Registry, &'static str> {
    static REGISTRY: OnceLock<Result<Registry, String>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| Registry::parse(SOURCE))
        .as_ref()
        .map_err(String::as_str)
}

fn get_str<'a>(t: &'a Table, key: &str, what: &str) -> Result<&'a str, String> {
    t.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("verbs.toml: {what}: missing string `{key}`"))
}

fn get_strs(t: &Table, key: &str, what: &str) -> Result<Vec<String>, String> {
    let items = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("verbs.toml: {what}: missing array `{key}`"))?;
    items
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("verbs.toml: {what}: `{key}` must hold strings"))
        })
        .collect()
}

fn table<'a>(doc: &'a toml::Document, name: &str) -> Result<&'a Table, String> {
    doc.tables
        .get(name)
        .ok_or_else(|| format!("verbs.toml: missing [{name}]"))
}

fn schemas(doc: &toml::Document, kind: &str) -> Result<Vec<Schema>, String> {
    let mut out: Vec<Schema> = Vec::new();
    for t in doc.arrays.get(kind).map(Vec::as_slice).unwrap_or_default() {
        let name = get_str(t, "name", kind)?.to_string();
        let what = format!("{kind} {name}");
        if !is_name(&name) || out.iter().any(|s| s.name == name) {
            return Err(format!("verbs.toml: {what}: invalid or duplicate name"));
        }
        let mut fields: Vec<Field> = Vec::new();
        for spec in get_strs(t, "fields", &what)? {
            let (field, type_text) = spec
                .split_once(':')
                .ok_or_else(|| format!("verbs.toml: {what}: field `{spec}` is not name:type"))?;
            if !is_name(field) || fields.iter().any(|f| f.name == field) {
                return Err(format!(
                    "verbs.toml: {what}: invalid or duplicate field `{field}`"
                ));
            }
            fields.push(Field {
                name: field.to_string(),
                type_text: type_text.to_string(),
                ty: Type::parse(type_text).map_err(|e| format!("verbs.toml: {what}: {e}"))?,
            });
        }
        out.push(Schema {
            doc: get_str(t, "doc", &what)?.to_string(),
            name,
            fields,
        });
    }
    Ok(out)
}

impl Registry {
    /// Parse and validate a registry document.
    pub fn parse(text: &str) -> Result<Self, String> {
        let doc = toml::parse(text).map_err(|e| format!("verbs.toml: {e}"))?;
        if doc.root.get("schema_version").and_then(Value::as_int) != Some(1) {
            return Err("verbs.toml: schema_version must be 1".into());
        }
        let env = table(&doc, "envelope")?;
        let envelope = Envelope {
            discriminator: get_str(env, "discriminator", "envelope")?.to_string(),
            description: get_str(env, "description", "envelope")?.to_string(),
        };
        let g = table(&doc, "global")?;
        let global = Global {
            flags: get_strs(g, "flags", "global")?,
            switches: get_strs(g, "switches", "global")?,
            events: get_strs(g, "events", "global")?,
            usage: get_str(g, "usage", "global")?.to_string(),
        };
        let mut verbs: Vec<Verb> = Vec::new();
        for t in doc
            .arrays
            .get("verb")
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let name = get_str(t, "name", "verb")?.to_string();
            let what = format!("verb {name}");
            let exits = t
                .get("exits")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("verbs.toml: {what}: missing array `exits`"))?
                .iter()
                .map(|v| v.as_int().and_then(|i| u8::try_from(i).ok()))
                .collect::<Option<Vec<u8>>>()
                .ok_or_else(|| format!("verbs.toml: {what}: exits must be small integers"))?;
            verbs.push(Verb {
                summary: get_str(t, "summary", &what)?.to_string(),
                writes: t
                    .get("writes")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| format!("verbs.toml: {what}: missing bool `writes`"))?,
                subcommands: get_strs(t, "subcommands", &what)?,
                flags: get_strs(t, "flags", &what)?,
                switches: get_strs(t, "switches", &what)?,
                events: get_strs(t, "events", &what)?,
                exits,
                usage: get_strs(t, "usage", &what)?,
                example: get_str(t, "example", &what)?.to_string(),
                name,
            });
        }
        let mut aliases = Vec::new();
        for t in doc
            .arrays
            .get("alias")
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let name = get_str(t, "name", "alias")?.to_string();
            let expands = get_strs(t, "expands", &format!("alias {name}"))?;
            aliases.push(Alias { name, expands });
        }
        let registry = Self {
            envelope,
            global,
            verbs,
            aliases,
            events: schemas(&doc, "event")?,
            shapes: schemas(&doc, "shape")?,
        };
        registry.validate()?;
        Ok(registry)
    }

    fn validate(&self) -> Result<(), String> {
        let mut names = BTreeSet::new();
        for v in &self.verbs {
            let ok_word =
                |w: &str| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
            if !ok_word(v.name.as_str()) || !names.insert(v.name.as_str()) {
                return Err(format!(
                    "verbs.toml: invalid or duplicate verb `{}`",
                    v.name
                ));
            }
            let subs: BTreeSet<_> = v.subcommands.iter().collect();
            if subs.len() != v.subcommands.len()
                || !v.subcommands.iter().all(|s| ok_word(s.as_str()))
            {
                return Err(format!("verbs.toml: verb {}: bad subcommands", v.name));
            }
            if v.usage.is_empty() || v.exits.first() != Some(&0) || v.exits.contains(&1) {
                return Err(format!(
                    "verbs.toml: verb {}: needs usage and exits starting at 0 (1 is never emitted)",
                    v.name
                ));
            }
            for e in &v.events {
                if self.event(e).is_none() {
                    return Err(format!(
                        "verbs.toml: verb {} emits undeclared event `{e}`",
                        v.name
                    ));
                }
            }
            for f in v.flags.iter().chain(&v.switches) {
                if self.global.flags.contains(f) || self.global.switches.contains(f) {
                    return Err(format!(
                        "verbs.toml: verb {} repeats the global flag {f}",
                        v.name
                    ));
                }
            }
        }
        // A flag name means one thing everywhere: it takes a value or it does not.
        let value_flags: BTreeSet<&str> = self.value_flags().into_iter().collect();
        for f in self.switches() {
            if value_flags.contains(f) {
                return Err(format!(
                    "verbs.toml: {f} is a value flag in one row and a switch in another"
                ));
            }
        }
        for f in value_flags.iter().chain(&self.switches()) {
            let body = f.strip_prefix("--").unwrap_or("");
            if body.is_empty() || !body.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
                return Err(format!("verbs.toml: bad flag `{f}`"));
            }
        }
        let mut alias_names = BTreeSet::new();
        for a in &self.aliases {
            if names.contains(a.name.as_str()) || !alias_names.insert(a.name.as_str()) {
                return Err(format!(
                    "verbs.toml: alias `{}` shadows a verb or repeats",
                    a.name
                ));
            }
            let target = a
                .expands
                .first()
                .and_then(|v| self.verb(v))
                .ok_or_else(|| {
                    format!("verbs.toml: alias `{}` does not expand to a verb", a.name)
                })?;
            match a.expands.get(1..).unwrap_or_default() {
                [] => {}
                [sub] if target.subcommands.contains(sub) => {}
                _ => {
                    return Err(format!(
                        "verbs.toml: alias `{}` expands past the verb's subcommands",
                        a.name
                    ));
                }
            }
        }
        for e in &self.global.events {
            if self.event(e).is_none() {
                return Err(format!("verbs.toml: global event `{e}` is undeclared"));
            }
        }
        for e in &self.events {
            if !self.global.events.contains(&e.name) && self.emitters(&e.name).is_empty() {
                return Err(format!(
                    "verbs.toml: event `{}` is emitted by no verb (dead schema)",
                    e.name
                ));
            }
            if e.fields
                .iter()
                .any(|f| f.name == self.envelope.discriminator)
            {
                return Err(format!(
                    "verbs.toml: event `{}` declares the discriminator as a field",
                    e.name
                ));
            }
        }
        for s in &self.shapes {
            if self.events.iter().any(|e| e.name == s.name) {
                return Err(format!(
                    "verbs.toml: `{}` is both an event and a shape",
                    s.name
                ));
            }
        }
        for schema in self.events.iter().chain(&self.shapes) {
            let mut refs = Vec::new();
            for f in &schema.fields {
                f.ty.shapes(&mut refs);
            }
            if let Some(missing) = refs.iter().find(|r| self.shape(r).is_none()) {
                return Err(format!(
                    "verbs.toml: `{}` names undeclared shape `{missing}`",
                    schema.name
                ));
            }
        }
        let reachable: BTreeSet<&str> = self
            .closure(&self.events.iter().collect::<Vec<_>>())
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        if let Some(dead) = self
            .shapes
            .iter()
            .find(|s| !reachable.contains(s.name.as_str()))
        {
            return Err(format!(
                "verbs.toml: shape `{}` is referenced by no event (dead schema)",
                dead.name
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn verb(&self, name: &str) -> Option<&Verb> {
        self.verbs.iter().find(|v| v.name == name)
    }

    #[must_use]
    pub fn alias(&self, name: &str) -> Option<&Alias> {
        self.aliases.iter().find(|a| a.name == name)
    }

    #[must_use]
    pub fn event(&self, name: &str) -> Option<&Schema> {
        self.events.iter().find(|e| e.name == name)
    }

    #[must_use]
    pub fn shape(&self, name: &str) -> Option<&Schema> {
        self.shapes.iter().find(|s| s.name == name)
    }

    /// The verbs that emit `event`, in registry order.
    #[must_use]
    pub fn emitters(&self, event: &str) -> Vec<&str> {
        self.verbs
            .iter()
            .filter(|v| v.events.iter().any(|e| e == event))
            .map(|v| v.name.as_str())
            .collect()
    }

    /// Every flag that takes a value, global or any verb's, sorted.
    #[must_use]
    pub fn value_flags(&self) -> Vec<&str> {
        let set: BTreeSet<&str> = self
            .global
            .flags
            .iter()
            .chain(self.verbs.iter().flat_map(|v| &v.flags))
            .map(String::as_str)
            .collect();
        set.into_iter().collect()
    }

    /// Every switch, global or any verb's, sorted.
    #[must_use]
    pub fn switches(&self) -> Vec<&str> {
        let set: BTreeSet<&str> = self
            .global
            .switches
            .iter()
            .chain(self.verbs.iter().flat_map(|v| &v.switches))
            .map(String::as_str)
            .collect();
        set.into_iter().collect()
    }

    /// The shapes `roots` reference, transitively, in registry order.
    #[must_use]
    pub fn closure(&self, roots: &[&Schema]) -> Vec<&Schema> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut queue: Vec<&Schema> = roots.to_vec();
        while let Some(schema) = queue.pop() {
            let mut refs = Vec::new();
            for f in &schema.fields {
                f.ty.shapes(&mut refs);
            }
            for r in refs {
                if seen.insert(r)
                    && let Some(s) = self.shape(r)
                {
                    queue.push(s);
                }
            }
        }
        self.shapes
            .iter()
            .filter(|s| seen.contains(s.name.as_str()))
            .collect()
    }

    /// Check one robot-mode stdout line: a JSON object whose discriminator
    /// names a declared event, carrying exactly that event's fields, each of
    /// its declared type. Returns the event name.
    pub fn check_line<'a>(&'a self, line: &str) -> Result<&'a str, String> {
        let value = json::parse(line).map_err(|e| format!("not JSON ({e}): {line}"))?;
        let Json::Obj(fields) = &value else {
            return Err(format!("not a JSON object: {line}"));
        };
        let name = value
            .get(&self.envelope.discriminator)
            .and_then(Json::as_str)
            .ok_or_else(|| format!("no `{}` string: {line}", self.envelope.discriminator))?;
        let event = self
            .event(name)
            .ok_or_else(|| format!("undeclared event `{name}`: {line}"))?;
        let rest: Vec<(String, Json)> = fields
            .iter()
            .filter(|(k, _)| *k != self.envelope.discriminator)
            .cloned()
            .collect();
        self.check_fields(&event.fields, &rest, name)
            .map_err(|e| format!("{e}\n  in: {line}"))?;
        Ok(&event.name)
    }

    fn check_fields(
        &self,
        declared: &[Field],
        actual: &[(String, Json)],
        at: &str,
    ) -> Result<(), String> {
        let want: BTreeSet<&str> = declared.iter().map(|f| f.name.as_str()).collect();
        let have: BTreeSet<&str> = actual.iter().map(|(k, _)| k.as_str()).collect();
        if want != have || have.len() != actual.len() {
            return Err(format!(
                "{at}: fields {have:?} (with {} entries) differ from the schema's {want:?}",
                actual.len()
            ));
        }
        for f in declared {
            let v = actual
                .iter()
                .find(|(k, _)| *k == f.name)
                .map(|(_, v)| v)
                .ok_or_else(|| format!("{at}.{}: missing", f.name))?;
            self.check_value(&f.ty, v, &format!("{at}.{}", f.name))?;
        }
        Ok(())
    }

    fn check_value(&self, ty: &Type, v: &Json, at: &str) -> Result<(), String> {
        let ok = match (ty, v) {
            (Type::Any, _) => true,
            (Type::Nullable(_), Json::Null) => true,
            (Type::Nullable(t), v) => return self.check_value(t, v, at),
            (Type::Object, Json::Obj(_)) => true,
            (Type::Array(t), Json::Arr(items)) => {
                for (i, item) in items.iter().enumerate() {
                    self.check_value(t, item, &format!("{at}[{i}]"))?;
                }
                true
            }
            (Type::Shape(name), Json::Obj(fields)) => {
                let shape = self
                    .shape(name)
                    .ok_or_else(|| format!("{at}: undeclared shape `{name}`"))?;
                return self.check_fields(&shape.fields, fields, at);
            }
            (Type::Scalar(s), v) => scalar_admits(*s, v),
            _ => false,
        };
        if ok {
            Ok(())
        } else {
            Err(format!("{at}: {} is not a {ty:?}", v.render()))
        }
    }
}

fn scalar_admits(s: Scalar, v: &Json) -> bool {
    match (s, v) {
        (Scalar::String | Scalar::Text, Json::Str(_)) | (Scalar::Int, Json::Int(_)) => true,
        (Scalar::Bool, Json::Bool(_)) => true,
        (Scalar::Seq, Json::Int(n)) => u64::try_from(*n).is_ok(),
        (Scalar::Hex, Json::Str(t)) => {
            !t.is_empty()
                && t.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        (Scalar::Date, Json::Str(t)) => {
            let b = t.as_bytes();
            b.len() == 10
                && b.iter().enumerate().all(|(i, c)| {
                    if i == 4 || i == 7 {
                        *c == b'-'
                    } else {
                        c.is_ascii_digit()
                    }
                })
        }
        (Scalar::Amount, Json::Str(t)) => {
            let Some((number, unit)) = t.split_once(' ') else {
                return false;
            };
            let digits = number.strip_prefix('-').unwrap_or(number);
            let (whole, frac) = digits.split_once('.').unwrap_or((digits, "0"));
            !whole.is_empty()
                && !frac.is_empty()
                && whole.bytes().all(|b| b.is_ascii_digit())
                && frac.bytes().all(|b| b.is_ascii_digit())
                && !unit.is_empty()
                && unit.bytes().all(|b| b.is_ascii_alphanumeric())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_registry_is_valid_and_consistent_with_the_exit_codes() {
        let r = registry().expect("verbs.toml");
        let exits = fa_registry::ExitCodes::embedded().expect("exit_codes.toml");
        for v in &r.verbs {
            for code in &v.exits {
                assert!(
                    exits.rows.iter().any(|row| row.code == *code),
                    "verb {} names exit {code}, which exit_codes.toml lacks",
                    v.name
                );
            }
        }
        for e in &r.events {
            if e.name == "usage_error" || e.name == "refusal" || e.name == "error" {
                assert!(e.fields.iter().any(|f| f.name == "exit"), "{}", e.name);
            }
        }
        assert!(r.value_flags().contains(&"--book"));
        assert!(r.switches().contains(&"--json"));
    }

    fn with(edit: impl Fn(&str) -> String) -> Result<Registry, String> {
        Registry::parse(&edit(SOURCE))
    }

    #[test]
    fn inconsistent_registries_are_refused() {
        let cases: Vec<(&str, Result<Registry, String>)> = vec![
            (
                "alias to a missing verb",
                with(|s| s.replace("expands = [\"tb\"]", "expands = [\"tbx\"]")),
            ),
            (
                "undeclared shape",
                with(|s| s.replace("\"rows:[tb_row]\"", "\"rows:[tb_rows]\"")),
            ),
            (
                "dead event",
                with(|s| s.replace("events = [\"trial_balance\"]", "events = []")),
            ),
            (
                "flag that is both a value flag and a switch",
                with(|s| s.replace("switches = [\"--activity\"]", "switches = [\"--period\"]")),
            ),
            (
                "duplicate verb",
                with(|s| s.replace("name = \"reserve\"", "name = \"post\"")),
            ),
            (
                "unknown type",
                with(|s| s.replace("\"balanced:bool\"", "\"balanced:boolean?\"")),
            ),
            (
                "exit 1",
                with(|s| s.replace("exits = [0, 2, 4, 5]", "exits = [0, 1]")),
            ),
        ];
        for (what, result) in cases {
            assert!(result.is_err(), "{what} was accepted");
        }
        // The edits above really changed the source (else this test is void).
        assert!(with(|s| s.to_string()).is_ok());
    }

    #[test]
    fn check_line_admits_exactly_the_schema() {
        let r = registry().expect("verbs.toml");
        let good = r#"{"entry_digest":"ab01","event":"recorded","recorded_at":7,"vid":"00ff"}"#;
        assert_eq!(r.check_line(good), Ok("recorded"));
        for bad in [
            // a missing field, an extra field, a wrong type, a negative
            // sequence, an uppercase hex, an unknown event, not an object
            r#"{"entry_digest":"ab01","event":"recorded","vid":"00ff"}"#,
            r#"{"entry_digest":"ab01","event":"recorded","extra":1,"recorded_at":7,"vid":"00ff"}"#,
            r#"{"entry_digest":"ab01","event":"recorded","recorded_at":"7","vid":"00ff"}"#,
            r#"{"entry_digest":"ab01","event":"recorded","recorded_at":-1,"vid":"00ff"}"#,
            r#"{"entry_digest":"AB01","event":"recorded","recorded_at":7,"vid":"00ff"}"#,
            r#"{"event":"recorded_twice"}"#,
            r#"["recorded"]"#,
        ] {
            assert!(r.check_line(bad).is_err(), "admitted {bad}");
        }
        let nested = r#"{"accounts":[{"code":"1000","leaf":true,"lower_bound":"0.00 USD","name":"Cash","type":"Asset","unit":"USD","upper_bound":null}],"event":"accounts"}"#;
        assert_eq!(r.check_line(nested), Ok("accounts"));
        let nested_bad = r#"{"accounts":[{"code":"1000","leaf":"yes","lower_bound":null,"name":"Cash","type":"Asset","unit":"USD","upper_bound":null}],"event":"accounts"}"#;
        assert!(r.check_line(nested_bad).is_err());
        for (amount, ok) in [
            ("1500.00 USD", true),
            ("-2100.00 USD", true),
            ("1500 JPY", true),
            ("1500.00", false),
            ("1.5e3 USD", false),
            (" USD", false),
        ] {
            assert_eq!(
                scalar_admits(Scalar::Amount, &Json::Str(amount.into())),
                ok,
                "{amount}"
            );
        }
        assert!(scalar_admits(Scalar::Date, &Json::Str("2026-03-15".into())));
        assert!(!scalar_admits(
            Scalar::Date,
            &Json::Str("2026-03-15T00:00".into())
        ));
    }
}
