#![forbid(unsafe_code)]
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

pub mod json;

use std::collections::BTreeSet;
use std::sync::OnceLock;

use fa_registry::toml::{self, Table, Value};

use crate::json::Json;

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

/// A registry name: lowercase ASCII letters, digits and `_`, starting with
/// a letter (`gate_g1`).
fn is_name(s: &str) -> bool {
    s.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
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
    /// An event that is always about one book: its envelope `coordinate` is
    /// never null. False for every shape.
    pub book: bool,
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

/// The top-level fields every robot-mode line carries beside its `event`
/// and its `data` (plan Appendix D), in the order the binary writes them.
pub const ENVELOPE_FIELDS: &[&str] = &[
    "v",
    "book",
    "coordinate",
    "certificate",
    "authority",
    "warnings",
    "next_actions",
];

/// The envelope version this binary writes (every line's `v`); the
/// registry's `[envelope] version` must agree.
pub const ENVELOPE_VERSION: i128 = 1;

/// The key that holds a line's event fields (the registry's `payload`).
pub const PAYLOAD: &str = "data";

/// The envelope fields an event about a book never leaves null.
pub const BOOK_FIELDS: &[&str] = &["book", "coordinate"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub discriminator: String,
    /// Every line's `v`.
    pub version: i128,
    /// The key holding the event's own fields ([`PAYLOAD`]).
    pub payload: String,
    /// [`ENVELOPE_FIELDS`], with their types.
    pub fields: Vec<Field>,
    /// Events that are wire frames (the daemon's protocol), not robot-mode
    /// lines: flat, with no envelope.
    pub frames: Vec<String>,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Global {
    pub flags: Vec<String>,
    pub switches: Vec<String>,
    /// Events emitted outside any one verb (errors, `--version`, triage, help).
    pub events: Vec<String>,
    /// The largest edit distance a "did you mean" correction spans.
    pub correction_distance: usize,
    pub usage: String,
}

/// When a dangerous operation needs confirmation (closed vocabulary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    /// Every invocation.
    Always,
    /// The command self-issues this op with `--grant`.
    Grant(String),
    /// The intent's disposition voids a hold.
    Voids,
    /// The period already has materialized register cells.
    ExistingCells,
}

impl Condition {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "always" => Some(Self::Always),
            "disposition:voids" => Some(Self::Voids),
            "existing-cells" => Some(Self::ExistingCells),
            other => other
                .strip_prefix("grant:")
                .filter(|op| is_name(op))
                .map(|op| Self::Grant(op.to_string())),
        }
    }

    /// The registry spelling.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Always => "always".into(),
            Self::Grant(op) => format!("grant:{op}"),
            Self::Voids => "disposition:voids".into(),
            Self::ExistingCells => "existing-cells".into(),
        }
    }

    /// Whether dispatch decides it from the command line alone, before the
    /// handler opens the book; the others are decided by their handler.
    #[must_use]
    pub fn from_argv(&self) -> bool {
        matches!(self, Self::Always | Self::Grant(_))
    }
}

/// An operation that cannot be undone in practice (plan §15.3, Appendix D
/// FA-REF-007): refused with exit 7 unless confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dangerous {
    pub verb: String,
    /// `None` for a verb without subcommands.
    pub subcommand: Option<String>,
    pub condition: Condition,
    /// The reversible or read-only alternative the refusal names.
    pub safe: String,
}

/// A command an agent usually runs after `after` (Appendix D `next_actions`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextAction {
    pub after: String,
    pub command: String,
    pub why: String,
}

/// The `fad` daemon's contract (plan §15.3, Appendix D): where its socket
/// and writer lease live in a book directory, the frame protocol's version
/// and limits, the daemon binary's own verbs and flags, and the events its
/// frames and its own output carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Daemon {
    pub binary: String,
    pub protocol: i128,
    /// File names inside the book directory.
    pub socket: String,
    pub lease: String,
    /// The largest frame payload either side sends or accepts.
    pub max_frame_bytes: usize,
    /// How long a connection may sit between frames before the daemon closes it.
    pub idle_timeout_ms: u64,
    /// Interval between daemon clock observations, in nanoseconds.
    pub tick_ns: u64,
    /// Maximum accounting entries per expiry or reversal batch in one cycle.
    pub sweep_batch: usize,
    /// Maximum UTC/monotonic elapsed-time disagreement admitted by the clock judge.
    pub clock_drift_ns: u64,
    pub verbs: Vec<String>,
    pub flags: Vec<String>,
    pub switches: Vec<String>,
    pub events: Vec<String>,
    pub usage: Vec<String>,
}

/// One launch-bound authority rule (`[[bound]]`, fa-mg2j): the capability
/// operations a launch-bound session (MCP, `fa --token`, fad tokens) must
/// hold to run a command. Rules are ordered: the first whose conditions all
/// hold decides, and a command no rule decides is not admitted on the bound
/// route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundRule {
    pub verbs: Vec<String>,
    /// The first positional after the verb: one of its registered
    /// subcommands, or for a verb with none, the word it reads there
    /// (`statement diff`). Empty: any, or none.
    pub subcommands: Vec<String>,
    /// The second positional; empty: any.
    pub args: Vec<String>,
    /// Flags or switches that must all be present.
    pub when_all: Vec<String>,
    /// Flags or switches of which at least one must be present; empty: no
    /// condition.
    pub when_any: Vec<String>,
    /// Flags or switches none of which may be present.
    pub unless_any: Vec<String>,
    /// A value flag whose value must be one of `values`.
    pub flag: Option<String>,
    pub values: Vec<String>,
    /// Capability op names (`registries/capability_caveats.toml`); empty:
    /// the command reads nothing from a book.
    pub ops: Vec<String>,
}

impl BoundRule {
    /// Whether this rule decides `verb` with `sub` and `arg` (the first two
    /// positionals after the verb), `present` telling whether a flag or
    /// switch was given and `value` a value flag's value.
    pub fn matches(
        &self,
        verb: &str,
        sub: Option<&str>,
        arg: Option<&str>,
        present: &dyn Fn(&str) -> bool,
        value: &dyn Fn(&str) -> Option<String>,
    ) -> bool {
        let listed = |set: &[String], item: Option<&str>| {
            set.is_empty() || item.is_some_and(|item| set.iter().any(|s| s == item))
        };
        self.verbs.iter().any(|v| v == verb)
            && listed(&self.subcommands, sub)
            && listed(&self.args, arg)
            && self.when_all.iter().all(|f| present(f))
            && (self.when_any.is_empty() || self.when_any.iter().any(|f| present(f)))
            && !self.unless_any.iter().any(|f| present(f))
            && self
                .flag
                .as_ref()
                .is_none_or(|f| value(f).is_some_and(|v| self.values.contains(&v)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    pub envelope: Envelope,
    pub global: Global,
    pub daemon: Daemon,
    pub verbs: Vec<Verb>,
    pub aliases: Vec<Alias>,
    pub dangerous: Vec<Dangerous>,
    pub next_actions: Vec<NextAction>,
    pub events: Vec<Schema>,
    pub shapes: Vec<Schema>,
    /// The launch-bound authority rules, in order.
    pub bound: Vec<BoundRule>,
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

/// A `fields = ["name:type", …]` list.
fn parse_fields(t: &Table, what: &str) -> Result<Vec<Field>, String> {
    let mut fields: Vec<Field> = Vec::new();
    for spec in get_strs(t, "fields", what)? {
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
    Ok(fields)
}

fn schemas(doc: &toml::Document, kind: &str) -> Result<Vec<Schema>, String> {
    let mut out: Vec<Schema> = Vec::new();
    for t in doc.arrays.get(kind).map(Vec::as_slice).unwrap_or_default() {
        let name = get_str(t, "name", kind)?.to_string();
        let what = format!("{kind} {name}");
        if !is_name(&name) || out.iter().any(|s| s.name == name) {
            return Err(format!("verbs.toml: {what}: invalid or duplicate name"));
        }
        let book = match t.get("book") {
            None => false,
            Some(v) if kind == "event" => v
                .as_bool()
                .ok_or_else(|| format!("verbs.toml: {what}: `book` must be a bool"))?,
            Some(_) => return Err(format!("verbs.toml: {what}: only an event names `book`")),
        };
        out.push(Schema {
            doc: get_str(t, "doc", &what)?.to_string(),
            book,
            fields: parse_fields(t, &what)?,
            name,
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
            version: env
                .get("version")
                .and_then(Value::as_int)
                .ok_or("verbs.toml: envelope: missing integer `version`")?,
            payload: get_str(env, "payload", "envelope")?.to_string(),
            fields: parse_fields(env, "envelope")?,
            frames: get_strs(env, "frames", "envelope")?,
            description: get_str(env, "description", "envelope")?.to_string(),
        };
        let g = table(&doc, "global")?;
        let global = Global {
            flags: get_strs(g, "flags", "global")?,
            switches: get_strs(g, "switches", "global")?,
            events: get_strs(g, "events", "global")?,
            correction_distance: g
                .get("correction_distance")
                .and_then(Value::as_int)
                .and_then(|d| usize::try_from(d).ok())
                .ok_or("verbs.toml: global: missing integer `correction_distance`")?,
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
        let mut dangerous = Vec::new();
        for t in doc
            .arrays
            .get("dangerous")
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let verb = get_str(t, "verb", "dangerous")?.to_string();
            let what = format!("dangerous {verb}");
            let condition = get_str(t, "condition", &what)?;
            dangerous.push(Dangerous {
                subcommand: match t.get("subcommand") {
                    None => None,
                    Some(v) => Some(
                        v.as_str()
                            .ok_or_else(|| {
                                format!("verbs.toml: {what}: `subcommand` must be a string")
                            })?
                            .to_string(),
                    ),
                },
                condition: Condition::parse(condition).ok_or_else(|| {
                    format!("verbs.toml: {what}: unknown condition `{condition}`")
                })?,
                safe: get_str(t, "safe", &what)?.to_string(),
                verb,
            });
        }
        let mut next_actions = Vec::new();
        for t in doc
            .arrays
            .get("next_action")
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let after = get_str(t, "after", "next_action")?.to_string();
            let what = format!("next_action after {after}");
            next_actions.push(NextAction {
                command: get_str(t, "command", &what)?.to_string(),
                why: get_str(t, "why", &what)?.to_string(),
                after,
            });
        }
        let d = table(&doc, "daemon")?;
        let int = |key: &str| {
            d.get(key)
                .and_then(Value::as_int)
                .ok_or_else(|| format!("verbs.toml: daemon: missing integer `{key}`"))
        };
        let daemon = Daemon {
            binary: get_str(d, "binary", "daemon")?.to_string(),
            protocol: int("protocol")?,
            socket: get_str(d, "socket", "daemon")?.to_string(),
            lease: get_str(d, "lease", "daemon")?.to_string(),
            max_frame_bytes: usize::try_from(int("max_frame_bytes")?)
                .map_err(|_| "verbs.toml: daemon: max_frame_bytes out of range".to_string())?,
            idle_timeout_ms: u64::try_from(int("idle_timeout_ms")?)
                .map_err(|_| "verbs.toml: daemon: idle_timeout_ms out of range".to_string())?,
            tick_ns: u64::try_from(int("tick_ns")?)
                .map_err(|_| "verbs.toml: daemon: tick_ns out of range".to_string())?,
            sweep_batch: usize::try_from(int("sweep_batch")?)
                .map_err(|_| "verbs.toml: daemon: sweep_batch out of range".to_string())?,
            clock_drift_ns: u64::try_from(int("clock_drift_ns")?)
                .map_err(|_| "verbs.toml: daemon: clock_drift_ns out of range".to_string())?,
            verbs: get_strs(d, "verbs", "daemon")?,
            flags: get_strs(d, "flags", "daemon")?,
            switches: get_strs(d, "switches", "daemon")?,
            events: get_strs(d, "events", "daemon")?,
            usage: get_strs(d, "usage", "daemon")?,
        };
        let mut bound = Vec::new();
        for (i, t) in doc
            .arrays
            .get("bound")
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let what = format!("bound rule {i}");
            const KEYS: [&str; 9] = [
                "verbs",
                "subcommands",
                "args",
                "when_all",
                "when_any",
                "unless_any",
                "flag",
                "values",
                "ops",
            ];
            if let Some(key) = t.keys().find(|k| !KEYS.contains(&k.as_str())) {
                return Err(format!("verbs.toml: {what}: unknown key `{key}`"));
            }
            let optional = |key: &str| -> Result<Vec<String>, String> {
                if t.contains_key(key) {
                    get_strs(t, key, &what)
                } else {
                    Ok(Vec::new())
                }
            };
            bound.push(BoundRule {
                verbs: get_strs(t, "verbs", &what)?,
                subcommands: optional("subcommands")?,
                args: optional("args")?,
                when_all: optional("when_all")?,
                when_any: optional("when_any")?,
                unless_any: optional("unless_any")?,
                flag: match t.get("flag") {
                    None => None,
                    Some(v) => Some(
                        v.as_str()
                            .ok_or_else(|| format!("verbs.toml: {what}: `flag` must be a string"))?
                            .to_string(),
                    ),
                },
                values: optional("values")?,
                ops: get_strs(t, "ops", &what)?,
            });
        }
        let registry = Self {
            envelope,
            global,
            daemon,
            verbs,
            aliases,
            dangerous,
            next_actions,
            events: schemas(&doc, "event")?,
            shapes: schemas(&doc, "shape")?,
            bound,
        };
        registry.validate()?;
        Ok(registry)
    }

    /// The first `[[bound]]` rule deciding this command line, with its
    /// index; `None` when no rule does (the command is not admitted on the
    /// launch-bound route).
    pub fn bound_rule(
        &self,
        verb: &str,
        sub: Option<&str>,
        arg: Option<&str>,
        present: &dyn Fn(&str) -> bool,
        value: &dyn Fn(&str) -> Option<String>,
    ) -> Option<(usize, &BoundRule)> {
        self.bound
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.matches(verb, sub, arg, present, value))
    }

    /// Every rule names registered verbs, their subcommands, flags each of
    /// its verbs (or the global table) accepts, and registered op names.
    fn validate_bound(&self) -> Result<(), String> {
        let caveats = fa_registry::capability_caveats::CapabilityCaveats::embedded()
            .map_err(|e| format!("verbs.toml: bound rules: {e}"))?;
        let op_names: BTreeSet<&str> = caveats.ops.iter().map(|o| o.name.as_str()).collect();
        for (i, rule) in self.bound.iter().enumerate() {
            let what = format!("verbs.toml: bound rule {i}");
            if rule.verbs.is_empty() {
                return Err(format!("{what}: names no verb"));
            }
            let mut verbs = Vec::with_capacity(rule.verbs.len());
            for name in &rule.verbs {
                verbs.push(
                    self.verb(name)
                        .ok_or_else(|| format!("{what}: unknown verb `{name}`"))?,
                );
            }
            for sub in &rule.subcommands {
                // A verb without registered subcommands takes the word as
                // its first positional (`statement diff`, `allocate approve`).
                if let Some(v) = verbs
                    .iter()
                    .find(|v| !v.subcommands.is_empty() && !v.subcommands.contains(sub))
                {
                    return Err(format!("{what}: `{sub}` is not a subcommand of {}", v.name));
                }
            }
            for flag in rule
                .when_all
                .iter()
                .chain(&rule.when_any)
                .chain(&rule.unless_any)
                .chain(rule.flag.iter())
            {
                let global =
                    self.global.flags.contains(flag) || self.global.switches.contains(flag);
                if let Some(v) = verbs.iter().find(|v| !global && !v.accepts(flag)) {
                    return Err(format!("{what}: {} does not accept {flag}", v.name));
                }
            }
            if rule.flag.is_some() == rule.values.is_empty() {
                return Err(format!("{what}: `flag` and `values` go together"));
            }
            let unique: BTreeSet<&str> = rule.ops.iter().map(String::as_str).collect();
            if unique.len() != rule.ops.len() {
                return Err(format!("{what}: an op is listed twice"));
            }
            if let Some(op) = rule.ops.iter().find(|op| !op_names.contains(op.as_str())) {
                return Err(format!("{what}: `{op}` is not a registered capability op"));
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        self.validate_bound()?;
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
        for e in &self.daemon.events {
            if self.event(e).is_none() {
                return Err(format!("verbs.toml: daemon event `{e}` is undeclared"));
            }
        }
        let d = &self.daemon;
        if d.protocol < 1
            || d.max_frame_bytes == 0
            || u32::try_from(d.max_frame_bytes).is_err()
            || d.idle_timeout_ms == 0
            || d.tick_ns == 0
            || d.sweep_batch == 0
            || d.sweep_batch > fa_model::limits::MAX_BATCH_ENTRIES
            || d.socket.contains('/')
            || d.lease.contains('/')
            || d.socket == d.lease
        {
            return Err(
                "verbs.toml: daemon: protocol ≥ 1, a frame limit that fits the 4-byte prefix, non-zero idle and tick intervals, sweep_batch within the model batch limit, and two distinct plain file names".into(),
            );
        }
        for e in &self.events {
            if !self.global.events.contains(&e.name)
                && !self.daemon.events.contains(&e.name)
                && self.emitters(&e.name).is_empty()
            {
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
        // The envelope (plan Appendix D): this binary's version, exactly the
        // fields it writes, the event's fields under `data`, `book` and
        // `coordinate` nullable (a book event tightens both), and frames that
        // are bookless events.
        let env = &self.envelope;
        let env_names: Vec<&str> = env.fields.iter().map(|f| f.name.as_str()).collect();
        if env.version != ENVELOPE_VERSION || env_names != ENVELOPE_FIELDS || env.payload != PAYLOAD
        {
            return Err(format!(
                "verbs.toml: envelope: version {ENVELOPE_VERSION} (this binary's), payload `{PAYLOAD}`, and exactly the fields {ENVELOPE_FIELDS:?}"
            ));
        }
        for name in BOOK_FIELDS {
            if !env
                .fields
                .iter()
                .any(|f| f.name == *name && matches!(f.ty, Type::Nullable(_)))
            {
                return Err(format!("verbs.toml: envelope: `{name}` must be nullable"));
            }
        }
        for frame in &env.frames {
            if !self.event(frame).is_some_and(|e| !e.book) {
                return Err(format!(
                    "verbs.toml: envelope frame `{frame}` is not a bookless event"
                ));
            }
        }
        if self.global.correction_distance > 2 {
            return Err("verbs.toml: global: correction_distance is at most 2".into());
        }
        // A dangerous operation is a real verb (and one of its subcommands
        // exactly when it has them) that can exit 7, with a safe
        // alternative; one row per (verb, subcommand, condition).
        let mut dangerous_rows = BTreeSet::new();
        for d in &self.dangerous {
            let verb = self
                .verb(&d.verb)
                .ok_or_else(|| format!("verbs.toml: dangerous names unknown verb `{}`", d.verb))?;
            let subcommand_ok = match &d.subcommand {
                None => verb.subcommands.is_empty(),
                Some(s) => verb.subcommands.contains(s),
            };
            if !subcommand_ok
                || !verb.exits.contains(&7)
                || d.safe.is_empty()
                || !dangerous_rows.insert((
                    d.verb.as_str(),
                    d.subcommand.as_deref(),
                    d.condition.text(),
                ))
            {
                return Err(format!(
                    "verbs.toml: dangerous {} {:?}: a subcommand exactly when the verb has them, exit 7 among its exits, a safe alternative, no repeat",
                    d.verb, d.subcommand
                ));
            }
        }
        for n in &self.next_actions {
            if self.event(&n.after).is_none()
                || env.frames.contains(&n.after)
                || !n.command.starts_with("fa ")
                || n.command.contains("--book")
                || n.why.is_empty()
            {
                return Err(format!(
                    "verbs.toml: next_action after `{}`: a robot-mode event, an `fa …` command without --book, and why",
                    n.after
                ));
            }
        }
        let envelope_schema = self.envelope_schema();
        for schema in self
            .events
            .iter()
            .chain(&self.shapes)
            .chain([&envelope_schema])
        {
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
        let mut roots: Vec<&Schema> = self.events.iter().collect();
        roots.push(&envelope_schema);
        let reachable: BTreeSet<&str> = self
            .closure(&roots)
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

    /// The envelope's fields as a schema (shape reachability, docs).
    fn envelope_schema(&self) -> Schema {
        Schema {
            name: "envelope".into(),
            doc: self.envelope.description.clone(),
            book: false,
            fields: self.envelope.fields.clone(),
        }
    }

    /// Whether `event` is a wire frame (no envelope).
    #[must_use]
    pub fn is_frame(&self, event: &str) -> bool {
        self.envelope.frames.iter().any(|f| f == event)
    }

    /// The top-level envelope fields one robot-mode line of `event` carries
    /// beside `event` and `data`, with `book` and `coordinate` never null on
    /// an event about a book. A wire frame carries none.
    #[must_use]
    pub fn envelope_fields(&self, event: &Schema) -> Vec<Field> {
        if self.is_frame(&event.name) {
            return Vec::new();
        }
        self.envelope
            .fields
            .iter()
            .map(|f| match &f.ty {
                Type::Nullable(inner) if event.book && BOOK_FIELDS.contains(&f.name.as_str()) => {
                    Field {
                        name: f.name.clone(),
                        type_text: f.type_text.trim_end_matches('?').to_string(),
                        ty: (**inner).clone(),
                    }
                }
                _ => f.clone(),
            })
            .collect()
    }

    /// The dangerous-operation rows for one verb and subcommand (`None` for
    /// a verb without subcommands), in registry order.
    pub fn dangerous_for<'a>(
        &'a self,
        verb: &'a str,
        subcommand: Option<&'a str>,
    ) -> impl Iterator<Item = &'a Dangerous> + 'a {
        self.dangerous
            .iter()
            .filter(move |d| d.verb == verb && d.subcommand.as_deref() == subcommand)
    }

    /// The commands an agent usually runs after `event`, in registry order.
    pub fn next_actions_for<'a>(
        &'a self,
        event: &'a str,
    ) -> impl Iterator<Item = &'a NextAction> + 'a {
        self.next_actions.iter().filter(move |n| n.after == event)
    }

    /// The operations in `required` (verb, subcommand, condition) that have
    /// no dangerous row: the dangerous-operation table test fails on any.
    #[must_use]
    pub fn ungated<'a>(
        &self,
        required: &[(&'a str, Option<&'a str>, &'a str)],
    ) -> Vec<(&'a str, Option<&'a str>, &'a str)> {
        required
            .iter()
            .copied()
            .filter(|(verb, sub, condition)| {
                !self
                    .dangerous_for(verb, *sub)
                    .any(|d| d.condition.text() == *condition)
            })
            .collect()
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

    /// Check one robot-mode stdout line (plan Appendix D): a JSON object
    /// whose discriminator names a declared event, carrying exactly the
    /// envelope's fields (`v` the envelope version; `book` and `coordinate`
    /// set on an event about a book) and, under `data`, exactly that event's
    /// fields, each of its declared type. A wire frame is flat: its own
    /// fields beside the discriminator. Returns the event name.
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
        if self.is_frame(name) {
            self.check_fields(&event.fields, &rest, name)
                .map_err(|e| format!("{e}\n  in: {line}"))?;
            return Ok(&event.name);
        }
        let mut top = self.envelope_fields(event);
        top.push(Field {
            name: self.envelope.payload.clone(),
            type_text: "object".into(),
            ty: Type::Object,
        });
        self.check_fields(&top, &rest, name)
            .map_err(|e| format!("{e}\n  in: {line}"))?;
        let Some(Json::Obj(data)) = value.get(&self.envelope.payload) else {
            return Err(format!(
                "{name}.{} is not an object\n  in: {line}",
                self.envelope.payload
            ));
        };
        self.check_fields(
            &event.fields,
            data,
            &format!("{name}.{}", self.envelope.payload),
        )
        .map_err(|e| format!("{e}\n  in: {line}"))?;
        if value.get("v") != Some(&Json::Int(self.envelope.version)) {
            return Err(format!(
                "{name}.v is not the envelope version {}\n  in: {line}",
                self.envelope.version
            ));
        }
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
        // One error event for every non-zero exit (Appendix D), and every
        // exit class the binary can name is a row of exit_codes.toml.
        let error = r.event("error").expect("the error event");
        for field in ["class", "exit", "refusal_id"] {
            assert!(error.fields.iter().any(|f| f.name == field), "{field}");
        }
        for gone in ["usage_error", "refusal", "verification_failed"] {
            assert!(r.event(gone).is_none(), "{gone} is folded into error");
        }
        assert!(exits.rows.iter().any(|row| row.name == "usage"));
        assert!(r.value_flags().contains(&"--book"));
        assert!(r.switches().contains(&"--json"));
    }

    fn with(edit: impl Fn(&str) -> String) -> Result<Registry, String> {
        let edited = edit(SOURCE);
        assert_ne!(
            edited, SOURCE,
            "a planted mutation must change the registry text"
        );
        Registry::parse(&edited)
    }

    #[test]
    fn registry_names_are_lowercase_words_with_digits_after_the_first_letter() {
        for good in ["gate_g1", "fad_request", "v", "next_actions"] {
            assert!(is_name(good), "{good}");
        }
        for bad in ["", "1gate", "_x", "Gate", "gate-g1", "gate g1"] {
            assert!(!is_name(bad), "{bad:?}");
        }
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
                with(|s| {
                    s.replace("events = [\"approved\"]", "events = []")
                        .replace(", \"approved\"", "")
                }),
            ),
            (
                "flag that is both a value flag and a switch",
                with(|s| {
                    s.replace(
                        "switches = [\"--activity\", \"--summary\", \"--certify\", \"--as-originally-reported\"]",
                        "switches = [\"--period\"]",
                    )
                }),
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
            (
                "an envelope without warnings",
                with(|s| s.replace("\"warnings:[string]\", ", "")),
            ),
            (
                "a payload key other than data",
                with(|s| s.replace("payload = \"data\"", "payload = \"body\"")),
            ),
            (
                "a non-nullable envelope coordinate",
                with(|s| s.replace("\"coordinate:coordinate?\"", "\"coordinate:coordinate\"")),
            ),
            (
                "a non-nullable envelope book",
                with(|s| s.replace("\"book:hex?\", \"coordinate", "\"book:hex\", \"coordinate")),
            ),
            (
                "an envelope version this binary does not write",
                with(|s| s.replace("version = 1\npayload", "version = 2\npayload")),
            ),
            (
                "a dangerous row naming an unknown verb",
                with(|s| s.replace("verb = \"resolve\"", "verb = \"resolv\"")),
            ),
            (
                "a dangerous verb that cannot exit 7",
                with(|s| {
                    // `recover` shares this exit set, so find the registers
                    // verb's own row rather than the first match.
                    let exits = "exits = [0, 2, 4, 5, 7, 8]";
                    let verb = s.find("name = \"registers\"").expect("the registers verb");
                    let at = verb + s[verb..].find(exits).expect("the registers exit row");
                    format!(
                        "{}exits = [0, 2, 4, 5, 8]{}",
                        &s[..at],
                        &s[at + exits.len()..]
                    )
                }),
            ),
            (
                "a dangerous row with an unknown condition",
                with(|s| {
                    s.replace(
                        "condition = \"existing-cells\"",
                        "condition = \"sometimes\"",
                    )
                }),
            ),
            (
                "a next action that names a book path",
                with(|s| {
                    s.replace(
                        "command = \"fa tb --period <code> --json\"",
                        "command = \"fa tb --period <code> --book ./b --json\"",
                    )
                }),
            ),
            (
                "a correction distance past 2",
                with(|s| s.replace("correction_distance = 1", "correction_distance = 3")),
            ),
        ];
        for (what, result) in cases {
            assert!(result.is_err(), "{what} was accepted");
        }
        // The unchanged source is the valid positive control.
        assert!(Registry::parse(SOURCE).is_ok());
    }

    const BOOK: &str = r#""0a1b""#;
    const COORDINATE: &str =
        r#"{"branch":"trunk","effective":"all","known_at":7,"time_evidence":null}"#;
    const RECORDED: &str =
        r#"{"entry_digest":"ab01","moved":null,"recorded_at":7,"requested":null,"vid":"00ff"}"#;

    /// One robot line (plan Appendix D): `data` (a JSON object) under
    /// `event`, with `book` and `coordinate` as given (JSON text).
    fn line(event: &str, data: &str, book: &str, coordinate: &str) -> String {
        format!(
            r#"{{"authority":{{"ops":null,"posture":"embedded-owner","principal":null,"profile":"Human"}},"book":{book},"certificate":null,"coordinate":{coordinate},"data":{data},"event":"{event}","next_actions":[],"v":1,"warnings":[]}}"#
        )
    }

    /// A line about the book `BOOK` at `COORDINATE`.
    fn booked(event: &str, data: &str) -> String {
        line(event, data, BOOK, COORDINATE)
    }

    /// The envelope (plan Appendix D) is part of every line's schema: an
    /// event about a book without its book or coordinate, payload fields
    /// outside `data`, a line without the envelope, a stale `v`, or a
    /// malformed next action fails `check_line`; a bookless event says null;
    /// the daemon's wire frames are flat.
    #[test]
    fn the_envelope_is_checked_on_every_line() {
        let r = registry().expect("verbs.toml");
        assert_eq!(r.check_line(&booked("recorded", RECORDED)), Ok("recorded"));
        // Planted negative: a handler that emits a book event without its
        // coordinate (null, or no key at all), or without its book, fails
        // the schema test.
        let null_coordinate = line("recorded", RECORDED, BOOK, "null");
        assert!(r.check_line(&null_coordinate).is_err(), "{null_coordinate}");
        let no_coordinate =
            booked("recorded", RECORDED).replace(&format!(r#""coordinate":{COORDINATE},"#), "");
        assert!(!no_coordinate.contains("coordinate"));
        assert!(r.check_line(&no_coordinate).is_err(), "{no_coordinate}");
        let null_book = line("recorded", RECORDED, "null", COORDINATE);
        assert!(r.check_line(&null_book).is_err(), "{null_book}");
        // The payload lives under `data`, nowhere else.
        let flat = r#"{"entry_digest":"ab01","event":"recorded","moved":null,"recorded_at":7,"requested":null,"vid":"00ff"}"#;
        assert!(r.check_line(flat).is_err(), "a line without the envelope");
        let no_data = booked("recorded", RECORDED).replace(&format!(r#""data":{RECORDED},"#), "");
        assert!(!no_data.contains("data"));
        assert!(r.check_line(&no_data).is_err(), "{no_data}");
        let beside = booked("recorded", RECORDED).replace(r#""v":1"#, r#""v":1,"vid":"00ff""#);
        assert!(r.check_line(&beside).is_err(), "{beside}");
        let stale = booked("recorded", RECORDED).replace(r#""v":1"#, r#""v":2"#);
        assert!(r.check_line(&stale).is_err(), "{stale}");
        let half_action = booked("recorded", RECORDED).replace(
            r#""next_actions":[]"#,
            r#""next_actions":[{"command":"fa tb --json"}]"#,
        );
        assert!(r.check_line(&half_action).is_err(), "{half_action}");
        let with_action = booked("recorded", RECORDED).replace(
            r#""next_actions":[]"#,
            r#""next_actions":[{"command":"fa tb --json","why":"the trial balance"}]"#,
        );
        assert_eq!(r.check_line(&with_action), Ok("recorded"));
        // A bookless event: null is the honest book and coordinate; the one
        // error event carries the exit's class and the refusal id.
        let usage = r#"{"class":"usage","cite":null,"detail":null,"exit":2,"fix":"fa --help","message":"unknown command","refusal_id":null}"#;
        assert_eq!(
            r.check_line(&line("error", usage, "null", "null")),
            Ok("error")
        );
        let refusal = r#"{"class":"safety","cite":"Appendix D FA-REF-007","detail":null,"exit":7,"fix":"fa period soft-close FY2026-P03","message":"not confirmed","refusal_id":"FA-REF-007"}"#;
        assert_eq!(r.check_line(&booked("error", refusal)), Ok("error"));
        let classless = r#"{"cite":null,"detail":null,"exit":2,"fix":"fa --help","message":"unknown command","refusal_id":null}"#;
        assert!(
            r.check_line(&line("error", classless, "null", "null"))
                .is_err()
        );
        // Wire frames are the daemon's protocol: flat, no envelope.
        let frame = r#"{"event":"fad_response","exit":0,"op":"run","stderr":"","stdout":"","v":1}"#;
        assert_eq!(r.check_line(frame), Ok("fad_response"));
        let wrapped = line(
            "fad_response",
            r#"{"exit":0,"op":"run","stderr":"","stdout":"","v":1}"#,
            "null",
            "null",
        );
        assert!(r.check_line(&wrapped).is_err(), "{wrapped}");
        // Every book event's envelope says so; no bookless one does.
        for e in &r.events {
            let types: Vec<(String, String)> = r
                .envelope_fields(e)
                .into_iter()
                .filter(|f| BOOK_FIELDS.contains(&f.name.as_str()))
                .map(|f| (f.name, f.type_text))
                .collect();
            let want: Vec<(String, String)> = match (r.is_frame(&e.name), e.book) {
                (true, _) => Vec::new(),
                (false, true) => vec![
                    ("book".into(), "hex".into()),
                    ("coordinate".into(), "coordinate".into()),
                ],
                (false, false) => vec![
                    ("book".into(), "hex?".into()),
                    ("coordinate".into(), "coordinate?".into()),
                ],
            };
            assert_eq!(types, want, "{}", e.name);
        }
    }

    #[test]
    fn check_line_admits_exactly_the_schema() {
        let r = registry().expect("verbs.toml");
        assert_eq!(r.check_line(&booked("recorded", RECORDED)), Ok("recorded"));
        let balanced = r#"{"entry_digest":"ab01","moved":"20.00 USD","recorded_at":7,"requested":"50.00 USD","vid":"00ff"}"#;
        assert_eq!(r.check_line(&booked("recorded", balanced)), Ok("recorded"));
        for (event, data) in [
            // a missing field, an extra field, a wrong type, a negative
            // sequence, an uppercase hex, a non-amount, an unknown event
            (
                "recorded",
                r#"{"entry_digest":"ab01","moved":null,"requested":null,"vid":"00ff"}"#,
            ),
            (
                "recorded",
                r#"{"entry_digest":"ab01","extra":1,"moved":null,"recorded_at":7,"requested":null,"vid":"00ff"}"#,
            ),
            (
                "recorded",
                r#"{"entry_digest":"ab01","moved":null,"recorded_at":"7","requested":null,"vid":"00ff"}"#,
            ),
            (
                "recorded",
                r#"{"entry_digest":"ab01","moved":null,"recorded_at":-1,"requested":null,"vid":"00ff"}"#,
            ),
            (
                "recorded",
                r#"{"entry_digest":"AB01","moved":null,"recorded_at":7,"requested":null,"vid":"00ff"}"#,
            ),
            (
                "recorded",
                r#"{"entry_digest":"ab01","moved":20,"recorded_at":7,"requested":null,"vid":"00ff"}"#,
            ),
            ("recorded_twice", "{}"),
        ] {
            let bad = booked(event, data);
            assert!(r.check_line(&bad).is_err(), "admitted {bad}");
        }
        assert!(r.check_line(r#"["recorded"]"#).is_err());
        let nested = r#"{"accounts":[{"code":"1000","leaf":true,"limit_scope":"lifetime","lower_bound":"0.00 USD","name":"Cash","type":"Asset","unit":"USD","upper_bound":null}]}"#;
        assert_eq!(r.check_line(&booked("accounts", nested)), Ok("accounts"));
        let nested_bad = r#"{"accounts":[{"code":"1000","leaf":"yes","limit_scope":null,"lower_bound":null,"name":"Cash","type":"Asset","unit":"USD","upper_bound":null}]}"#;
        assert!(r.check_line(&booked("accounts", nested_bad)).is_err());
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

#[cfg(test)]
mod bound_tests {
    use super::*;

    /// The ops the embedded `[[bound]]` rules give a command line.
    fn ops(
        verb: &str,
        sub: Option<&str>,
        arg: Option<&str>,
        present: &[&str],
        values: &[(&str, &str)],
    ) -> Option<Vec<String>> {
        let reg = Registry::parse(SOURCE).expect("the embedded registry");
        let present = |flag: &str| present.contains(&flag);
        let value = |flag: &str| {
            values
                .iter()
                .find(|(f, _)| *f == flag)
                .map(|(_, v)| (*v).to_string())
        };
        reg.bound_rule(verb, sub, arg, &present, &value)
            .map(|(_, rule)| rule.ops.clone())
    }

    fn names(ops: &[&str]) -> Option<Vec<String>> {
        Some(ops.iter().map(|o| (*o).to_string()).collect())
    }

    #[test]
    fn the_first_matching_rule_decides_and_an_undecided_command_is_not_admitted() {
        assert_eq!(ops("post", None, None, &[], &[]), names(&["post"]));
        assert_eq!(ops("help", None, None, &[], &[]), names(&[]));
        // A plan or dry run of a transition reads; the transition itself is
        // host-only.
        assert_eq!(
            ops(
                "period",
                Some("open"),
                Some("FY2026-P03"),
                &["--dry-run"],
                &[]
            ),
            names(&["read"])
        );
        assert_eq!(
            ops(
                "period",
                Some("open"),
                Some("FY2026-P03"),
                &["--dry-run", "--plan"],
                &[]
            ),
            None
        );
        assert_eq!(
            ops("period", Some("open"), Some("FY2026-P03"), &[], &[]),
            None
        );
        // Certification needs produce beside read.
        assert_eq!(ops("gl", Some("detail"), None, &[], &[]), names(&["read"]));
        assert_eq!(
            ops("gl", Some("detail"), None, &["--certify"], &[]),
            names(&["read", "produce"])
        );
        assert_eq!(ops("tb", None, None, &["--certify"], &[]), names(&["read"]));
        assert_eq!(
            ops("tb", None, None, &["--summary", "--certify"], &[]),
            names(&["read", "produce"])
        );
        // The second positional and flags narrow a subcommand.
        assert_eq!(
            ops("document", Some("hold"), Some("list"), &[], &[]),
            names(&["read"])
        );
        assert_eq!(
            ops("document", Some("hold"), Some("place"), &[], &[]),
            names(&["hold"])
        );
        assert_eq!(
            ops(
                "document",
                Some("attest"),
                Some("register-equals"),
                &["--account"],
                &[]
            ),
            names(&["reconcile"])
        );
        assert_eq!(
            ops(
                "document",
                Some("attest"),
                Some("register-equals"),
                &[],
                &[]
            ),
            names(&["read"])
        );
        assert_eq!(ops("document", Some("add"), None, &["--grade"], &[]), None);
        assert_eq!(
            ops("allocate", Some("approve"), None, &[], &[]),
            names(&["read", "approve"])
        );
        assert_eq!(
            ops(
                "migrate",
                Some("import"),
                None,
                &["--action"],
                &[("--action", "stage")]
            ),
            names(&["read", "post", "migrate"])
        );
        assert_eq!(
            ops(
                "migrate",
                Some("import"),
                None,
                &["--action"],
                &[("--action", "commit")]
            ),
            None
        );
        // Host-only commands have no rule.
        for (verb, sub) in [
            ("party", "identifiers"),
            ("book", "create"),
            ("chart", "import"),
            ("capability", "issue"),
        ] {
            assert_eq!(ops(verb, Some(sub), None, &[], &[]), None, "{verb} {sub}");
        }
    }

    fn planted(from: &str, to: &str) -> Result<Registry, String> {
        assert_eq!(SOURCE.matches(from).count(), 1, "anchor {from:?}");
        Registry::parse(&SOURCE.replacen(from, to, 1))
    }

    #[test]
    fn a_rule_naming_anything_unregistered_is_refused() {
        let witness = "verbs = [\"checkpoint\"]\nops = [\"witness\"]";
        for (what, result, expected) in [
            (
                "unknown verb",
                planted(witness, "verbs = [\"checkpoints\"]\nops = [\"witness\"]"),
                "unknown verb `checkpoints`",
            ),
            (
                "unknown op",
                planted(witness, "verbs = [\"checkpoint\"]\nops = [\"witnes\"]"),
                "`witnes` is not a registered capability op",
            ),
            (
                "unknown key",
                planted(
                    witness,
                    "verbs = [\"checkpoint\"]\nwhen = [\"--to\"]\nops = [\"witness\"]",
                ),
                "unknown key `when`",
            ),
            (
                "unregistered subcommand",
                planted("subcommands = [\"promote\"]", "subcommands = [\"promot\"]"),
                "`promot` is not a subcommand of draft",
            ),
            (
                "flag the verb does not accept",
                planted("when_any = [\"--to\"]", "when_any = [\"--too\"]"),
                "document does not accept --too",
            ),
            (
                "flag without values",
                planted("values = [\"show\"]\n", ""),
                "`flag` and `values` go together",
            ),
            (
                "an op listed twice",
                planted("ops = [\"read\", \"verify\"]", "ops = [\"read\", \"read\"]"),
                "an op is listed twice",
            ),
        ] {
            let error = result.expect_err(what);
            assert!(error.contains(expected), "{what}: {error}");
        }
    }
}
