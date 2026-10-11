//! The `[mcp]` section of `registries/verbs.toml` (plan §15.4): the tool
//! clusters, the registered exclusions, and each tool's positionals, read
//! beside the verb registry [`fa_cli::verbs`] parses. Everything a host sees
//! — wire names, input schemas, the Do / Don't / Discovery / Examples /
//! Common-mistakes documentation, the argv a call becomes — is derived here
//! from the registry rows; nothing about a verb is hand-maintained in a
//! second place.
//!
//! [`McpRegistry::parse`] refuses an inconsistent section: a tool naming a
//! verb or subcommand the registry lacks, a cluster over the limit, a verb or
//! subcommand that is neither a tool nor a registered exclusion, one that is
//! both, or one covered by two tools. The parity test runs it over the
//! embedded registry and over planted defects.

use std::collections::{BTreeMap, BTreeSet};

use fa_cli::args;
use fa_cli::verbs::{Registry, Verb};
use fa_registry::toml::{self, Table, Value};
use fastmcp_rust::{JsonMap, JsonValue, json};

/// The registry text this build embeds (the same bytes `fa` embeds).
pub const SOURCE: &str = fa_cli::verbs::SOURCE;

/// The properties every tool carries beside its verb's own.
const BOOK: &str = "book";
const AS: &str = "as";
const KEYS: &str = "keys";
const YES: &str = "yes";

/// The resources the server exposes (plan §15.4; only what exists today).
pub const RESOURCES: &[(&str, &str)] = &[
    (
        "resource://fa/book",
        "the served book's identity and size (`fa book info`)",
    ),
    (
        "resource://fa/chart/{book}",
        "a book's chart of accounts (`fa chart list`); `{book}` is the book directory, percent-encoded, or `default` for the served book",
    ),
    (
        "resource://fa/periods/{book}",
        "a book's periods with their states (`fa period list`); `{book}` as above",
    ),
    (
        "resource://fa/laws",
        "the law registries this build enforces, verbatim TOML: entry classes, the admissibility matrix, rounding laws, units, the evidence policy, the SoD policy, reason codes, the refusal catalog, account types, limits",
    ),
    (
        "resource://fa/exit-codes",
        "the exit-code dictionary (`fa capabilities` → exit_codes)",
    ),
    (
        "resource://fa/intents",
        "the intent documents this build accepts: the entry classes and the worked examples (`fa robot-docs examples`); a machine-readable intent schema is not registered yet (fa-intents is planned)",
    ),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cluster {
    pub name: String,
    pub doc: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Excluded {
    pub verb: String,
    pub subcommand: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Positional {
    pub name: String,
    pub required: bool,
}

/// What kind of JSON a forwarded stdin property holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdinKind {
    /// A JSON object, forwarded as its JSON text.
    Object,
    /// A string, forwarded as its bytes.
    Text,
}

/// A JSON property the server forwards on stdin as the `-` argument of
/// `via` (a value flag spelled `--flag`, or a positional's name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StdinSpec {
    pub property: String,
    pub kind: StdinKind,
    pub via: String,
}

/// One tool: a verb, or some of a verb's subcommands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolSpec {
    pub cluster: String,
    pub name: String,
    pub verb: String,
    /// The subcommands this tool covers (empty for a verb without any).
    pub subcommands: Vec<String>,
    /// The property that picks the subcommand when several are covered.
    pub selector: Option<String>,
    pub positionals: Vec<Positional>,
    /// The verb's value flags this tool exposes (`--spelling`).
    pub flags: Vec<String>,
    /// The verb's switches this tool exposes (`--spelling`).
    pub switches: Vec<String>,
    /// Flags (`--spelling`), positionals and stdin properties the host must supply.
    pub required: Vec<String>,
    pub stdin: Option<StdinSpec>,
    pub dont: Vec<String>,
    pub mistakes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpRegistry {
    pub server: String,
    pub max_tools_per_cluster: usize,
    pub hidden_flags: Vec<String>,
    pub repeat_flags: Vec<String>,
    pub integer_flags: Vec<String>,
    pub clusters: Vec<Cluster>,
    pub tools: Vec<ToolSpec>,
    pub excluded: Vec<Excluded>,
}

/// A tool call as the structured error's `suggested_tool_calls`, the
/// envelope's `next_actions` and the generated examples spell one.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    pub tool: String,
    pub arguments: JsonValue,
    /// The `fa …` command line it was derived from.
    pub command: String,
}

impl ToolCall {
    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        json!({
            "tool": self.tool,
            "arguments": self.arguments,
            "command": self.command,
        })
    }
}

/// The argv and stdin one tool call becomes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub argv: Vec<String>,
    pub stdin: Option<Vec<u8>>,
}

/// An argument the mapping cannot accept (usage class).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgError {
    pub message: String,
    pub fix: String,
}

fn get_str<'a>(t: &'a Table, key: &str, what: &str) -> Result<&'a str, String> {
    t.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("verbs.toml [mcp]: {what}: missing string `{key}`"))
}

fn get_strs(t: &Table, key: &str, what: &str) -> Result<Vec<String>, String> {
    let items = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("verbs.toml [mcp]: {what}: missing array `{key}`"))?;
    items
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("verbs.toml [mcp]: {what}: `{key}` must hold strings"))
        })
        .collect()
}

fn opt_strs(t: &Table, key: &str, what: &str) -> Result<Option<Vec<String>>, String> {
    if t.contains_key(key) {
        get_strs(t, key, what).map(Some)
    } else {
        Ok(None)
    }
}

/// `--as-known-at` → `as_known_at`: a flag's property name.
#[must_use]
pub fn property(flag: &str) -> String {
    flag.trim_start_matches("--").replace('-', "_")
}

impl McpRegistry {
    /// The `[mcp]` section of the embedded registry, validated against the
    /// embedded verb registry.
    pub fn embedded() -> Result<Self, String> {
        let reg = fa_cli::verbs::registry().map_err(str::to_string)?;
        Self::parse(SOURCE, reg)
    }

    /// Parse and validate the `[mcp]` section of `text` against `reg` (the
    /// verb registry parsed from the same text, or a planted variant).
    pub fn parse(text: &str, reg: &Registry) -> Result<Self, String> {
        let doc = toml::parse(text).map_err(|e| format!("verbs.toml: {e}"))?;
        let m = doc.tables.get("mcp").ok_or("verbs.toml: missing [mcp]")?;
        let max = m
            .get("max_tools_per_cluster")
            .and_then(Value::as_int)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("verbs.toml [mcp]: missing positive integer `max_tools_per_cluster`")?;
        let mut clusters = Vec::new();
        for t in doc
            .arrays
            .get("mcp.cluster")
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            clusters.push(Cluster {
                name: get_str(t, "name", "cluster")?.to_string(),
                doc: get_str(t, "doc", "cluster")?.to_string(),
            });
        }
        let mut excluded = Vec::new();
        for t in doc
            .arrays
            .get("mcp.excluded")
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let verb = get_str(t, "verb", "excluded")?.to_string();
            let what = format!("excluded {verb}");
            excluded.push(Excluded {
                subcommand: match t.get("subcommand") {
                    None => None,
                    Some(v) => Some(
                        v.as_str()
                            .ok_or_else(|| {
                                format!("verbs.toml [mcp]: {what}: `subcommand` must be a string")
                            })?
                            .to_string(),
                    ),
                },
                reason: get_str(t, "reason", &what)?.to_string(),
                verb,
            });
        }
        let mut tools = Vec::new();
        for t in doc
            .arrays
            .get("mcp.tool")
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let cluster = get_str(t, "cluster", "tool")?.to_string();
            let name = get_str(t, "name", "tool")?.to_string();
            let what = format!("tool {cluster}.{name}");
            let verb = get_str(t, "verb", &what)?.to_string();
            let positionals = get_strs(t, "positionals", &what)?
                .into_iter()
                .map(|p| match p.strip_suffix('?') {
                    Some(n) => Positional {
                        name: n.to_string(),
                        required: false,
                    },
                    None => Positional {
                        name: p,
                        required: true,
                    },
                })
                .collect();
            let stdin = match t.get("stdin_property") {
                None => None,
                Some(_) => {
                    let kind = match get_str(t, "stdin_kind", &what)? {
                        "object" => StdinKind::Object,
                        "string" => StdinKind::Text,
                        other => {
                            return Err(format!(
                                "verbs.toml [mcp]: {what}: stdin_kind `{other}` is not object|string"
                            ));
                        }
                    };
                    Some(StdinSpec {
                        property: get_str(t, "stdin_property", &what)?.to_string(),
                        kind,
                        via: get_str(t, "stdin_via", &what)?.to_string(),
                    })
                }
            };
            let subcommands = get_strs(t, "subcommands", &what)?;
            let selector = match t.get("selector") {
                None => None,
                Some(v) => Some(
                    v.as_str()
                        .ok_or_else(|| {
                            format!("verbs.toml [mcp]: {what}: `selector` must be a string")
                        })?
                        .to_string(),
                ),
            };
            let verb_row = reg
                .verb(&verb)
                .ok_or_else(|| format!("verbs.toml [mcp]: {what}: names unknown verb `{verb}`"))?;
            let flags = opt_strs(t, "flags", &what)?.unwrap_or_else(|| verb_row.flags.clone());
            let switches =
                opt_strs(t, "switches", &what)?.unwrap_or_else(|| verb_row.switches.clone());
            tools.push(ToolSpec {
                cluster,
                name,
                verb,
                subcommands,
                selector,
                positionals,
                flags,
                switches,
                required: get_strs(t, "required", &what)?,
                stdin,
                dont: get_strs(t, "dont", &what)?,
                mistakes: get_strs(t, "mistakes", &what)?,
            });
        }
        let mcp = Self {
            server: get_str(m, "server", "mcp")?.to_string(),
            max_tools_per_cluster: max,
            hidden_flags: get_strs(m, "hidden_flags", "mcp")?,
            repeat_flags: get_strs(m, "repeat_flags", "mcp")?,
            integer_flags: get_strs(m, "integer_flags", "mcp")?,
            clusters,
            tools,
            excluded,
        };
        mcp.validate(reg)?;
        Ok(mcp)
    }

    fn validate(&self, reg: &Registry) -> Result<(), String> {
        let err = |m: String| Err(format!("verbs.toml [mcp]: {m}"));
        let global: BTreeSet<&str> = reg
            .global
            .flags
            .iter()
            .chain(&reg.global.switches)
            .map(String::as_str)
            .collect();
        for g in ["--book", "--as", "--keys", "--yes"] {
            if !global.contains(g) {
                return err(format!(
                    "the global flag {g} this server exposes is not in [global]"
                ));
            }
        }
        for h in &self.hidden_flags {
            if !global.contains(h.as_str()) {
                return err(format!("hidden flag {h} is not a [global] flag or switch"));
            }
        }
        let value_flags: BTreeSet<&str> = reg.value_flags().into_iter().collect();
        for f in self.repeat_flags.iter().chain(&self.integer_flags) {
            if !value_flags.contains(f.as_str()) {
                return err(format!(
                    "{f} (repeat/integer) is not a registered value flag"
                ));
            }
        }
        let mut cluster_names = BTreeSet::new();
        for c in &self.clusters {
            let ok = c
                .name
                .strip_prefix("fa.")
                .is_some_and(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()));
            if !ok || !cluster_names.insert(c.name.as_str()) || c.doc.is_empty() {
                return err(format!(
                    "cluster `{}`: a unique `fa.<word>` name with a doc",
                    c.name
                ));
            }
        }
        let mut per_cluster: BTreeMap<&str, usize> = BTreeMap::new();
        let mut wire_names = BTreeSet::new();
        // (verb, subcommand) → how many tools cover it.
        let mut covered: BTreeMap<(String, Option<String>), usize> = BTreeMap::new();
        for t in &self.tools {
            let what = format!("tool {}.{}", t.cluster, t.name);
            if !cluster_names.contains(t.cluster.as_str()) {
                return err(format!("{what}: unknown cluster"));
            }
            if t.name.is_empty()
                || !t
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return err(format!(
                    "{what}: a tool name is lowercase words joined by `_`"
                ));
            }
            if !wire_names.insert(t.wire_name()) {
                return err(format!("{what}: duplicate tool"));
            }
            *per_cluster.entry(t.cluster.as_str()).or_default() += 1;
            let verb = reg
                .verb(&t.verb)
                .ok_or_else(|| format!("verbs.toml [mcp]: {what}: unknown verb `{}`", t.verb))?;
            if verb.subcommands.is_empty() {
                if !t.subcommands.is_empty() || t.selector.is_some() {
                    return err(format!("{what}: verb `{}` has no subcommands", t.verb));
                }
                *covered.entry((t.verb.clone(), None)).or_default() += 1;
            } else {
                if t.subcommands.is_empty() {
                    return err(format!(
                        "{what}: name the subcommands of `{}` it covers",
                        t.verb
                    ));
                }
                let mut seen = BTreeSet::new();
                for sc in &t.subcommands {
                    if !verb.subcommands.contains(sc) || !seen.insert(sc) {
                        return err(format!(
                            "{what}: `{sc}` is not a subcommand of `{}` (or repeats)",
                            t.verb
                        ));
                    }
                    *covered
                        .entry((t.verb.clone(), Some(sc.clone())))
                        .or_default() += 1;
                }
                if (t.subcommands.len() > 1) != t.selector.is_some() {
                    return err(format!(
                        "{what}: a selector exactly when several subcommands are covered"
                    ));
                }
            }
            for f in &t.flags {
                if !verb.flags.contains(f) {
                    return err(format!("{what}: {f} is not a flag of `{}`", t.verb));
                }
            }
            for f in &t.switches {
                if !verb.switches.contains(f) {
                    return err(format!("{what}: {f} is not a switch of `{}`", t.verb));
                }
            }
            // Property names: unique, and never one of the server's own.
            let mut props: BTreeSet<String> = BTreeSet::new();
            let reserved = [BOOK, AS, KEYS, YES];
            let mut add = |p: String| -> Result<(), String> {
                if reserved.contains(&p.as_str()) || !props.insert(p.clone()) {
                    return Err(format!(
                        "verbs.toml [mcp]: {what}: property `{p}` repeats or is reserved"
                    ));
                }
                Ok(())
            };
            if let Some(sel) = &t.selector {
                add(sel.clone())?;
            }
            for p in &t.positionals {
                add(p.name.clone())?;
            }
            for f in t.flags.iter().chain(&t.switches) {
                let via_flag = t.stdin.as_ref().is_some_and(|s| &s.via == f);
                add(if via_flag {
                    format!("{}_file", property(f))
                } else {
                    property(f)
                })?;
            }
            if let Some(s) = &t.stdin {
                add(s.property.clone())?;
                let via_ok =
                    t.flags.contains(&s.via) || t.positionals.iter().any(|p| p.name == s.via);
                if !via_ok {
                    return err(format!(
                        "{what}: stdin_via `{}` is neither an exposed flag nor a positional",
                        s.via
                    ));
                }
            }
            for r in &t.required {
                let known = t.flags.contains(r)
                    || t.positionals.iter().any(|p| &p.name == r)
                    || t.stdin.as_ref().is_some_and(|s| &s.property == r)
                    || r == BOOK;
                if !known {
                    return err(format!(
                        "{what}: required `{r}` is not a flag, positional, stdin property or `book`"
                    ));
                }
            }
        }
        for (name, n) in &per_cluster {
            if *n > self.max_tools_per_cluster {
                return err(format!(
                    "cluster `{name}` has {n} tools; at most {} (plan §15.4)",
                    self.max_tools_per_cluster
                ));
            }
        }
        for c in &self.clusters {
            if !per_cluster.contains_key(c.name.as_str()) {
                return err(format!("cluster `{}` has no tools", c.name));
            }
        }
        // Exclusions name a verb (and one of its subcommands, when it has
        // them) or a daemon verb, with a reason; never twice.
        let mut excluded: BTreeSet<(String, Option<String>)> = BTreeSet::new();
        for e in &self.excluded {
            let what = format!("excluded {} {:?}", e.verb, e.subcommand);
            let ok = if e.verb == reg.daemon.binary {
                e.subcommand
                    .as_ref()
                    .is_some_and(|s| reg.daemon.verbs.contains(s))
            } else {
                match (reg.verb(&e.verb), &e.subcommand) {
                    (Some(v), None) => v.subcommands.is_empty(),
                    (Some(v), Some(s)) => v.subcommands.contains(s),
                    (None, _) => false,
                }
            };
            if !ok
                || e.reason.is_empty()
                || !excluded.insert((e.verb.clone(), e.subcommand.clone()))
            {
                return err(format!(
                    "{what}: a registered verb/subcommand (or daemon verb), a reason, no repeat"
                ));
            }
        }
        // Coverage: every verb and subcommand is a tool in exactly one
        // cluster, or a registered exclusion — never neither, never both.
        for v in &reg.verbs {
            let units: Vec<(String, Option<String>)> = if v.subcommands.is_empty() {
                vec![(v.name.clone(), None)]
            } else {
                v.subcommands
                    .iter()
                    .map(|s| (v.name.clone(), Some(s.clone())))
                    .collect()
            };
            for unit in units {
                let n = covered.get(&unit).copied().unwrap_or(0);
                let ex = excluded.contains(&unit);
                let spelled = match &unit.1 {
                    Some(s) => format!("{} {s}", unit.0),
                    None => unit.0.clone(),
                };
                match (n, ex) {
                    (0, false) => {
                        return err(format!(
                            "`{spelled}` is neither a tool nor a registered exclusion"
                        ));
                    }
                    (1, false) | (0, true) => {}
                    (_, true) => {
                        return err(format!("`{spelled}` is both a tool and an exclusion"));
                    }
                    (n, false) => return err(format!("`{spelled}` is covered by {n} tools")),
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn cluster(&self, name: &str) -> Option<&Cluster> {
        self.clusters.iter().find(|c| c.name == name)
    }

    /// The tools of one cluster, in registry order.
    pub fn tools_of<'a>(&'a self, cluster: &'a str) -> impl Iterator<Item = &'a ToolSpec> + 'a {
        self.tools.iter().filter(move |t| t.cluster == cluster)
    }

    #[must_use]
    pub fn tool_by_wire(&self, wire: &str) -> Option<&ToolSpec> {
        self.tools.iter().find(|t| t.wire_name() == wire)
    }

    /// The tool covering `verb` (and `subcommand`, for a verb that has them).
    #[must_use]
    pub fn tool_for(&self, verb: &str, subcommand: Option<&str>) -> Option<&ToolSpec> {
        self.tools.iter().find(|t| {
            t.verb == verb
                && match subcommand {
                    None => t.subcommands.is_empty(),
                    Some(s) => t.subcommands.iter().any(|x| x == s),
                }
        })
    }

    #[must_use]
    pub fn is_repeat(&self, flag: &str) -> bool {
        self.repeat_flags.iter().any(|f| f == flag)
    }

    #[must_use]
    pub fn is_integer(&self, flag: &str) -> bool {
        self.integer_flags.iter().any(|f| f == flag)
    }

    /// Translate an `fa …` command line (a refusal's fix, a next action, a
    /// registry example) into the tool call that runs it. `None` when the
    /// line is not an `fa` command this server exposes (`fad …`, prose).
    #[must_use]
    pub fn command_to_call(&self, reg: &Registry, command: &str) -> Option<ToolCall> {
        let tokens = shell_split(command);
        let (first, rest) = tokens.split_first()?;
        if first != "fa" {
            return None;
        }
        let parsed = args::parse(rest, &reg.value_flags(), &reg.switches()).ok()?;
        let word = parsed.positional.first()?;
        let expanded: Vec<String> = match reg.alias(word) {
            Some(a) => a.expands.clone(),
            None => vec![word.clone()],
        };
        let mut positional: Vec<String> = expanded;
        positional.extend(parsed.positional.iter().skip(1).cloned());
        let verb = reg.verb(&positional[0])?;
        let (sub, rest_from) = if verb.subcommands.is_empty() {
            (None, 1)
        } else {
            (positional.get(1).map(String::as_str), 2)
        };
        let tool = self.tool_for(&verb.name, sub)?;
        let mut arguments = JsonMap::new();
        if let (Some(sel), Some(s)) = (&tool.selector, sub) {
            arguments.insert(sel.clone(), JsonValue::String(s.to_string()));
        }
        for (i, p) in tool.positionals.iter().enumerate() {
            if let Some(v) = positional.get(rest_from + i) {
                arguments.insert(p.name.clone(), JsonValue::String(v.clone()));
            }
        }
        for (flag, values) in &parsed.flags {
            let prop = match flag.as_str() {
                "--book" => BOOK.to_string(),
                "--as" => AS.to_string(),
                "--keys" => KEYS.to_string(),
                f if self.hidden_flags.iter().any(|h| h == f) => continue,
                f if tool.flags.iter().any(|x| x == f) => {
                    if tool.stdin.as_ref().is_some_and(|s| s.via == f) {
                        format!("{}_file", property(f))
                    } else {
                        property(f)
                    }
                }
                _ => continue,
            };
            let value = if self.is_repeat(flag) {
                JsonValue::Array(
                    values
                        .iter()
                        .map(|v| JsonValue::String(v.clone()))
                        .collect(),
                )
            } else {
                JsonValue::String(values.last().cloned().unwrap_or_default())
            };
            arguments.insert(prop, value);
        }
        for sw in &parsed.switches {
            match sw.as_str() {
                "--yes" => {
                    arguments.insert(YES.to_string(), JsonValue::Bool(true));
                }
                f if tool.switches.iter().any(|x| x == f) => {
                    arguments.insert(property(f), JsonValue::Bool(true));
                }
                _ => {}
            }
        }
        Some(ToolCall {
            tool: tool.wire_name(),
            arguments: JsonValue::Object(arguments),
            command: command.to_string(),
        })
    }

    /// The tool calls named in free text: every backticked `fa …` command,
    /// and a line that is itself an `fa …` command.
    #[must_use]
    pub fn calls_in_text(&self, reg: &Registry, text: &str) -> Vec<ToolCall> {
        let mut out = Vec::new();
        let mut push = |cmd: &str| {
            if let Some(call) = self.command_to_call(reg, cmd.trim())
                && !out.iter().any(|c: &ToolCall| c.command == call.command)
            {
                out.push(call);
            }
        };
        let mut rest = text;
        while let Some(start) = rest.find('`') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('`') else { break };
            push(&after[..end]);
            rest = &after[end + 1..];
        }
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("fa ") {
                // A bare command ends at a comment, a `;` or a `, then …` clause.
                let cmd = line.split(" #").next().unwrap_or(line);
                let cmd = cmd.split("; ").next().unwrap_or(cmd);
                let cmd = cmd.split(", ").next().unwrap_or(cmd);
                push(cmd);
            }
        }
        out
    }

    /// The server's instructions text: the clusters, the rules every call
    /// obeys, and the resources.
    #[must_use]
    pub fn instructions(&self) -> String {
        let mut text = String::from(
            "FrankenAccounting over MCP: every tool runs one `fa` verb through the same dispatcher the CLI and the daemon use, so a refusal is byte-identical whichever way it was asked. Start with `fa_orient_capabilities`. Rules: amounts are strings with their unit (\"1500.00 USD\"), never JSON numbers; dates are civil YYYY-MM-DD, never instants; recorded time is assigned by the journal; corrections are new entries (Reversal, Replacement, Reclassification) — nothing is edited in place; never balance an entry by inventing a leg, never re-date an entry to dodge the period law, never approve your own proposal, never cite a placeholder. A tool's first content block is the robot envelope's `data`; the second is the envelope (book, coordinate, warnings, next_actions as tool calls). A tool error carries {type, message, recoverable, fix_hint, suggested_tool_calls, exit, refusal_id, cite, detail}: do the fix.\n\nClusters:\n",
        );
        for c in &self.clusters {
            let names: Vec<String> = self.tools_of(&c.name).map(ToolSpec::wire_name).collect();
            text.push_str(&format!(
                "- {} — {} Tools: {}\n",
                c.name,
                c.doc,
                names.join(", ")
            ));
        }
        text.push_str("\nExit classes (an error's `type`): ");
        let exits = fa_registry::ExitCodes::embedded()
            .map(|e| e.rows)
            .unwrap_or_default();
        let classes: Vec<String> = exits
            .iter()
            .filter(|r| r.code != 0)
            .map(|r| format!("{} ({})", r.name, r.code))
            .collect();
        text.push_str(&classes.join(" · "));
        text.push_str(".\n\nResources:\n");
        for (uri, doc) in RESOURCES {
            text.push_str(&format!("- {uri} — {doc}\n"));
        }
        text
    }
}

impl ToolSpec {
    /// `fa.read` + `trial_balance` → `fa_read_trial_balance`.
    #[must_use]
    pub fn wire_name(&self) -> String {
        format!("{}_{}", self.cluster.replace('.', "_"), self.name)
    }

    /// Whether any covered subcommand has a `[[dangerous]]` row (then the
    /// tool takes `yes`).
    #[must_use]
    pub fn is_dangerous(&self, reg: &Registry) -> bool {
        if self.subcommands.is_empty() {
            reg.dangerous_for(&self.verb, None).next().is_some()
        } else {
            self.subcommands
                .iter()
                .any(|s| reg.dangerous_for(&self.verb, Some(s)).next().is_some())
        }
    }

    /// The property that carries a flag: `--intent` → `intent`, or
    /// `intent_file` when the flag is the stdin property's `via`.
    #[must_use]
    pub fn flag_property(&self, flag: &str) -> String {
        if self.stdin.as_ref().is_some_and(|s| s.via == flag) {
            format!("{}_file", property(flag))
        } else {
            property(flag)
        }
    }

    /// Every property the input schema declares, in schema order.
    #[must_use]
    pub fn property_names(&self, reg: &Registry) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(sel) = &self.selector {
            names.push(sel.clone());
        }
        names.extend(self.positionals.iter().map(|p| p.name.clone()));
        if let Some(s) = &self.stdin {
            names.push(s.property.clone());
        }
        names.extend(self.flags.iter().map(|f| self.flag_property(f)));
        names.extend(self.switches.iter().map(|f| property(f)));
        if self.is_dangerous(reg) {
            names.push(YES.into());
        }
        names.push(BOOK.into());
        names.push(AS.into());
        names.push(KEYS.into());
        names
    }

    /// The JSON Schema of the tool's arguments, derived from the registry.
    #[must_use]
    pub fn input_schema(&self, mcp: &McpRegistry, reg: &Registry) -> JsonValue {
        let verb = reg.verb(&self.verb);
        let mut props = JsonMap::new();
        let mut required: Vec<String> = Vec::new();
        if let Some(sel) = &self.selector {
            props.insert(
                sel.clone(),
                json!({
                    "type": "string",
                    "enum": self.subcommands,
                    "description": format!("which `fa {}` subcommand to run", self.verb),
                }),
            );
            required.push(sel.clone());
        }
        for p in &self.positionals {
            let doc = match &self.stdin {
                Some(s) if s.via == p.name => format!(
                    "a path (relative to the server's working directory); or pass `{}` inline instead",
                    s.property
                ),
                _ => format!("the `<{}>` argument of `fa {}`", p.name, self.verb),
            };
            props.insert(
                p.name.clone(),
                json!({ "type": "string", "description": doc }),
            );
            if p.required {
                required.push(p.name.clone());
            }
        }
        if let Some(s) = &self.stdin {
            let (ty, what) = match s.kind {
                StdinKind::Object => ("object", "the document, inline"),
                StdinKind::Text => ("string", "the text, inline"),
            };
            let alt = if s.via.starts_with("--") {
                self.flag_property(&s.via)
            } else {
                s.via.clone()
            };
            props.insert(
                s.property.clone(),
                json!({
                    "type": ty,
                    "description": format!("{what}; forwarded on stdin as `{} -`. Exactly one of `{}` and `{alt}`.", s.via, s.property),
                }),
            );
        }
        let usage = verb.map(|v| v.usage.join(" · ")).unwrap_or_default();
        for f in &self.flags {
            let prop = self.flag_property(f);
            let mut schema = JsonMap::new();
            if mcp.is_repeat(f) {
                schema.insert("type".into(), json!(["string", "array"]));
                schema.insert("items".into(), json!({ "type": "string" }));
            } else if mcp.is_integer(f) {
                schema.insert("type".into(), json!(["string", "integer"]));
            } else {
                schema.insert("type".into(), json!("string"));
            }
            let doc = if self.stdin.as_ref().is_some_and(|s| &s.via == f) {
                format!(
                    "`{f} <path>` (a file path); or pass the document inline as `{}`",
                    self.stdin.as_ref().map_or("", |s| s.property.as_str())
                )
            } else {
                format!("`{f}` of `fa {}` ({})", self.verb, flag_hint(f, &usage))
            };
            schema.insert("description".into(), JsonValue::String(doc));
            props.insert(prop, JsonValue::Object(schema));
        }
        for f in &self.switches {
            props.insert(
                property(f),
                json!({ "type": "boolean", "description": format!("`{f}` of `fa {}`", self.verb) }),
            );
        }
        if self.is_dangerous(reg) {
            let safes: Vec<String> = self
                .dangerous_rows(reg)
                .map(|d| format!("{}: {}", d.condition.text(), d.safe))
                .collect();
            props.insert(
                YES.into(),
                json!({
                    "type": "boolean",
                    "description": format!("confirm an operation that cannot be undone in practice (`--yes`, FA-REF-007). Without it the call is refused with the safe alternative. Conditions — {}", safes.join("; ")),
                }),
            );
        }
        props.insert(BOOK.into(), json!({ "type": "string", "description": "the book directory (`--book`); the server's own book when absent" }));
        props.insert(AS.into(), json!({ "type": "string", "description": "the principal acting (`--as`; default operator)" }));
        props.insert(KEYS.into(), json!({ "type": "string", "description": "the book's key file (`--keys`; default <book>/book.keys)" }));
        for r in &self.required {
            // A path flag or positional can be satisfied by the inline
            // property. Requiring only the path in the published schema
            // would make a conforming MCP host reject the inline form.
            // Invocation validation below enforces exactly one input.
            if self.stdin.as_ref().is_some_and(|s| &s.via == r) {
                continue;
            }
            let prop = if r.starts_with("--") {
                property(r)
            } else {
                r.clone()
            };
            if !required.contains(&prop) {
                required.push(prop);
            }
        }
        json!({
            "type": "object",
            "properties": props,
            "required": required,
            "additionalProperties": false,
        })
    }

    /// The `[[dangerous]]` rows the covered subcommands carry.
    pub fn dangerous_rows<'a>(
        &'a self,
        reg: &'a Registry,
    ) -> impl Iterator<Item = &'a fa_cli::verbs::Dangerous> + 'a {
        reg.dangerous.iter().filter(move |d| {
            d.verb == self.verb
                && match &d.subcommand {
                    None => self.subcommands.is_empty(),
                    Some(s) => self.subcommands.contains(s),
                }
        })
    }

    /// The events the covered verb emits (the robot schemas of `data`).
    #[must_use]
    pub fn events<'a>(&self, reg: &'a Registry) -> Vec<&'a str> {
        reg.verb(&self.verb)
            .map(|v| v.events.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// The tool's documentation in the Do / Don't / Discovery / Examples /
    /// Common-mistakes form, generated from the registry rows.
    #[must_use]
    pub fn description(&self, mcp: &McpRegistry, reg: &Registry) -> String {
        let Some(verb) = reg.verb(&self.verb) else {
            return String::new();
        };
        let mut d = String::new();
        if self.subcommands.is_empty() || self.subcommands.len() == verb.subcommands.len() {
            d.push_str(&verb.summary);
        } else {
            d.push_str(&format!(
                "`fa {} {}`: {}",
                self.verb,
                self.subcommands.join("|"),
                verb.summary
            ));
        }
        d.push_str("\n\nDo:\n");
        for u in self.usage_lines(verb) {
            d.push_str(&format!("- fa {u}\n"));
        }
        d.push_str("Don't:\n");
        for row in self.dangerous_rows(reg) {
            let when = match &row.condition {
                fa_cli::verbs::Condition::Always => String::new(),
                c => format!(" when {}", condition_phrase(c)),
            };
            let op = match &row.subcommand {
                Some(s) => format!("`{s}`"),
                None => "this".to_string(),
            };
            d.push_str(&format!(
                "- Don't run {op}{when} without `yes: true` unless it is intended; it cannot be undone in practice (FA-REF-007). The safe alternative: {}\n",
                row.safe
            ));
        }
        for line in &self.dont {
            d.push_str(&format!("- {line}\n"));
        }
        if verb.writes && self.dont.is_empty() && self.dangerous_rows(reg).next().is_none() {
            d.push_str("- Don't retry a refusal unchanged: do the fix it names.\n");
        }
        d.push_str("Discovery:\n");
        let mut any = false;
        for ev in &verb.events {
            for n in reg.next_actions_for(ev) {
                let call = mcp.command_to_call(reg, &n.command);
                let target = call.map_or_else(
                    || format!("`{}`", n.command),
                    |c| format!("`{}` ({})", c.tool, n.command),
                );
                d.push_str(&format!("- after `{ev}`: {target} — {}\n", n.why));
                any = true;
            }
        }
        if !any {
            d.push_str("- `fa_orient_capabilities` lists every verb, exit code and dangerous operation; `fa_orient_robot_docs` (topic `schema`, name an event) prints the fields of `data`.\n");
        }
        let resources: Vec<&str> = RESOURCES.iter().map(|(u, _)| *u).collect();
        d.push_str(&format!("- resources: {}\n", resources.join(", ")));
        d.push_str("Examples:\n");
        let mut examples = Vec::new();
        if let Some(call) = mcp.command_to_call(reg, &verb.example)
            && call.tool == self.wire_name()
        {
            examples.push(call);
        }
        for u in self.usage_lines(verb) {
            if examples.len() >= 2 {
                break;
            }
            let cmd = format!("fa {}", strip_usage_decoration(&u));
            if let Some(call) = mcp.command_to_call(reg, &cmd)
                && call.tool == self.wire_name()
                && !examples.iter().any(|e| e.arguments == call.arguments)
            {
                examples.push(call);
            }
        }
        for e in &examples {
            d.push_str(&format!("- {} {}   ← {}\n", e.tool, e.arguments, e.command));
        }
        if examples.is_empty() {
            d.push_str(&format!("- {} {{}}\n", self.wire_name()));
        }
        d.push_str("Common mistakes:\n");
        for m in &self.mistakes {
            d.push_str(&format!("- {m}\n"));
        }
        d.push_str("- Amounts as JSON numbers (write \"1500.00 USD\"); instants where a civil date is required (write YYYY-MM-DD); placeholders such as \"<document oid>\" or TODO — all refused before dispatch.\n");
        let exits = fa_registry::ExitCodes::embedded()
            .map(|e| e.rows)
            .unwrap_or_default();
        let codes: Vec<String> = verb
            .exits
            .iter()
            .map(|c| {
                let name = exits
                    .iter()
                    .find(|r| r.code == *c)
                    .map_or("?", |r| r.name.as_str());
                format!("{c} {name}")
            })
            .collect();
        d.push_str(&format!("Exits: {}.\n", codes.join(" · ")));
        d.push_str(&format!(
            "Returns: `data` of event {} (fields: `fa_orient_robot_docs` topic schema).",
            verb.events
                .iter()
                .map(|e| format!("`{e}`"))
                .collect::<Vec<_>>()
                .join(" or ")
        ));
        d
    }

    /// The verb's usage lines this tool covers.
    fn usage_lines(&self, verb: &Verb) -> Vec<String> {
        verb.usage
            .iter()
            .filter(|u| {
                if self.subcommands.is_empty() || !u.starts_with(&verb.name) {
                    // Prose lines ("Stock balances include …") belong to every tool of the verb.
                    return true;
                }
                // `period lock|reopen <code> …`: the word after the verb names the subcommands.
                let after = u[verb.name.len()..].trim_start();
                let head = after.split(' ').next().unwrap_or("");
                head.split('|')
                    .any(|w| self.subcommands.iter().any(|s| s == w))
            })
            .cloned()
            .collect()
    }

    /// Map a call's arguments to the argv and stdin the front door runs.
    pub fn invocation(
        &self,
        mcp: &McpRegistry,
        reg: &Registry,
        arguments: &JsonValue,
        default_book: Option<&str>,
    ) -> Result<Invocation, ArgError> {
        let wire = self.wire_name();
        let empty = JsonMap::new();
        let obj = match arguments {
            JsonValue::Null => &empty,
            JsonValue::Object(o) => o,
            other => {
                return Err(ArgError {
                    message: format!(
                        "{wire}: arguments must be a JSON object, not {}",
                        kind_of(other)
                    ),
                    fix: format!("{wire} {{ … }} with the properties its input schema names"),
                });
            }
        };
        let known = self.property_names(reg);
        for key in obj.keys() {
            if !known.iter().any(|k| k == key) {
                let candidates: Vec<&str> = known.iter().map(String::as_str).collect();
                let fix = match args::nearest(key, &candidates) {
                    Some(n) => format!("did you mean `{n}`?"),
                    None => format!("the properties of {wire}: {}", known.join(", ")),
                };
                return Err(ArgError {
                    message: format!("{wire}: unknown argument `{key}`"),
                    fix,
                });
            }
        }
        let str_of = |name: &str| -> Result<Option<String>, ArgError> {
            match obj.get(name) {
                None | Some(JsonValue::Null) => Ok(None),
                Some(JsonValue::String(s)) => Ok(Some(s.clone())),
                Some(JsonValue::Number(n))
                    if mcp.integer_flags.iter().any(|f| property(f) == name) =>
                {
                    Ok(Some(n.to_string()))
                }
                Some(other) => Err(ArgError {
                    message: format!("{wire}: `{name}` must be a string, not {}", kind_of(other)),
                    fix: format!("`{name}`: \"…\""),
                }),
            }
        };
        let mut argv = vec![self.verb.clone()];
        let mut stdin: Option<Vec<u8>> = None;
        if let Some(sel) = &self.selector {
            let subs = &self.subcommands;
            let Some(choice) = str_of(sel)? else {
                return Err(ArgError {
                    message: format!("{wire}: `{sel}` is required"),
                    fix: format!("`{sel}`: one of {}", subs.join("|")),
                });
            };
            if !subs.contains(&choice) {
                let candidates: Vec<&str> = subs.iter().map(String::as_str).collect();
                return Err(ArgError {
                    message: format!(
                        "{wire}: `{sel}` `{choice}` is not one of {}",
                        subs.join("|")
                    ),
                    fix: args::nearest(&choice, &candidates).map_or_else(
                        || format!("`{sel}`: one of {}", subs.join("|")),
                        |n| format!("did you mean `{n}`?"),
                    ),
                });
            }
            argv.push(choice);
        } else if let [one] = self.subcommands.as_slice() {
            // Validated: a selector exactly when several subcommands are covered.
            argv.push(one.clone());
        }
        // The stdin property, when given, is forwarded as `-` for its via.
        let forwarded = match &self.stdin {
            Some(s) => match obj.get(&s.property) {
                None | Some(JsonValue::Null) => None,
                Some(v) => {
                    let bytes = match (s.kind, v) {
                        (StdinKind::Object, JsonValue::Object(_)) => v.to_string().into_bytes(),
                        (StdinKind::Text, JsonValue::String(t)) => t.clone().into_bytes(),
                        (StdinKind::Object, other) => {
                            return Err(ArgError {
                                message: format!(
                                    "{wire}: `{}` must be a JSON object, not {}",
                                    s.property,
                                    kind_of(other)
                                ),
                                fix: format!(
                                    "`{}`: {{ … }} (the document itself), or `{}` with a path",
                                    s.property,
                                    self.via_property(s)
                                ),
                            });
                        }
                        (StdinKind::Text, other) => {
                            return Err(ArgError {
                                message: format!(
                                    "{wire}: `{}` must be a string, not {}",
                                    s.property,
                                    kind_of(other)
                                ),
                                fix: format!(
                                    "`{}`: \"…\" (the text itself), or `{}` with a path",
                                    s.property,
                                    self.via_property(s)
                                ),
                            });
                        }
                    };
                    stdin = Some(bytes);
                    Some(s)
                }
            },
            None => None,
        };
        for p in &self.positionals {
            let via_here = forwarded.is_some_and(|s| s.via == p.name);
            let value = str_of(&p.name)?;
            match (via_here, value) {
                (true, Some(_)) => {
                    let s = forwarded.map_or("", |s| s.property.as_str());
                    return Err(ArgError {
                        message: format!("{wire}: both `{s}` and `{}` were given", p.name),
                        fix: format!("exactly one of `{s}` (inline) and `{}` (a path)", p.name),
                    });
                }
                (true, None) => argv.push("-".into()),
                (false, Some(v)) => argv.push(v),
                (false, None) if p.required => {
                    return Err(ArgError {
                        message: format!("{wire}: `{}` is required", p.name),
                        fix: format!(
                            "`{}`: \"…\" (the `<{}>` of `fa {}`)",
                            p.name, p.name, self.verb
                        ),
                    });
                }
                (false, None) => {
                    if self
                        .positionals
                        .iter()
                        .skip_while(|q| q.name != p.name)
                        .skip(1)
                        .any(|q| obj.contains_key(&q.name))
                    {
                        return Err(ArgError {
                            message: format!(
                                "{wire}: `{}` is needed before the arguments after it",
                                p.name
                            ),
                            fix: format!("`{}`: \"…\"", p.name),
                        });
                    }
                }
            }
        }
        for f in &self.flags {
            let prop = self.flag_property(f);
            let via_here = forwarded.is_some_and(|s| &s.via == f);
            match obj.get(&prop) {
                None | Some(JsonValue::Null) => {
                    if via_here {
                        argv.push(f.clone());
                        argv.push("-".into());
                    }
                }
                Some(_) if via_here => {
                    let s = forwarded.map_or("", |s| s.property.as_str());
                    return Err(ArgError {
                        message: format!("{wire}: both `{s}` and `{prop}` were given"),
                        fix: format!("exactly one of `{s}` (inline) and `{prop}` (a path)"),
                    });
                }
                Some(JsonValue::Array(items)) if mcp.is_repeat(f) => {
                    for item in items {
                        let JsonValue::String(v) = item else {
                            return Err(ArgError {
                                message: format!(
                                    "{wire}: `{prop}` holds a {} where a string is required",
                                    kind_of(item)
                                ),
                                fix: format!("`{prop}`: [\"…\", …]"),
                            });
                        };
                        argv.push(f.clone());
                        argv.push(v.clone());
                    }
                }
                Some(JsonValue::Array(_)) => {
                    return Err(ArgError {
                        message: format!("{wire}: `{prop}` takes one value"),
                        fix: format!("`{prop}`: \"…\""),
                    });
                }
                Some(JsonValue::Number(n)) if mcp.is_integer(f) && n.is_i64() => {
                    argv.push(f.clone());
                    argv.push(n.to_string());
                }
                Some(JsonValue::String(v)) => {
                    argv.push(f.clone());
                    argv.push(v.clone());
                }
                Some(other) => {
                    return Err(ArgError {
                        message: format!(
                            "{wire}: `{prop}` must be a string, not {}",
                            kind_of(other)
                        ),
                        fix: format!("`{prop}`: \"…\""),
                    });
                }
            }
        }
        for f in &self.switches {
            let prop = property(f);
            match obj.get(&prop) {
                None | Some(JsonValue::Null) | Some(JsonValue::Bool(false)) => {}
                Some(JsonValue::Bool(true)) => argv.push(f.clone()),
                Some(other) => {
                    return Err(ArgError {
                        message: format!(
                            "{wire}: `{prop}` must be a boolean, not {}",
                            kind_of(other)
                        ),
                        fix: format!("`{prop}`: true"),
                    });
                }
            }
        }
        if self.is_dangerous(reg) {
            match obj.get(YES) {
                None | Some(JsonValue::Null) | Some(JsonValue::Bool(false)) => {}
                Some(JsonValue::Bool(true)) => argv.push("--yes".into()),
                Some(other) => {
                    return Err(ArgError {
                        message: format!("{wire}: `yes` must be a boolean, not {}", kind_of(other)),
                        fix: "`yes`: true only when the operation is intended".into(),
                    });
                }
            }
        }
        // What the host must supply.
        for r in &self.required {
            let present = if r.starts_with("--") {
                let via = self.stdin.as_ref().filter(|s| &s.via == r);
                obj.contains_key(&self.flag_property(r))
                    || via.is_some_and(|s| obj.contains_key(&s.property))
            } else if r == BOOK {
                obj.contains_key(BOOK)
            } else {
                obj.contains_key(r)
                    || self
                        .stdin
                        .as_ref()
                        .is_some_and(|s| &s.via == r && obj.contains_key(&s.property))
            };
            if !present {
                let spelled = if r.starts_with("--") {
                    self.flag_property(r)
                } else {
                    r.clone()
                };
                let alt = self
                    .stdin
                    .as_ref()
                    .filter(|s| &s.via == r)
                    .map(|s| format!(" (or `{}` inline)", s.property))
                    .unwrap_or_default();
                return Err(ArgError {
                    message: format!("{wire}: `{spelled}` is required{alt}"),
                    fix: format!("`{spelled}`: …{alt}"),
                });
            }
        }
        if let Some(s) = &self.stdin
            && self.required.iter().any(|r| r == &s.property)
            && stdin.is_none()
            && !obj.contains_key(&self.via_property(s))
        {
            return Err(ArgError {
                message: format!(
                    "{wire}: `{}` (inline) or `{}` (a path) is required",
                    s.property,
                    self.via_property(s)
                ),
                fix: format!("`{}`: {{ … }}", s.property),
            });
        }
        if let Some(a) = str_of(AS)? {
            argv.push("--as".into());
            argv.push(a);
        }
        if let Some(k) = str_of(KEYS)? {
            argv.push("--keys".into());
            argv.push(k);
        }
        if let Some(b) = str_of(BOOK)?.as_deref().or(default_book) {
            argv.push("--book".into());
            argv.push(b.to_string());
        }
        argv.push("--json".into());
        Ok(Invocation { argv, stdin })
    }

    /// The path-form property beside a stdin property (`intent_file`, `file`).
    #[must_use]
    pub fn via_property(&self, s: &StdinSpec) -> String {
        if s.via.starts_with("--") {
            self.flag_property(&s.via)
        } else {
            s.via.clone()
        }
    }
}

fn kind_of(v: &JsonValue) -> &'static str {
    match v {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "a boolean",
        JsonValue::Number(_) => "a number",
        JsonValue::String(_) => "a string",
        JsonValue::Array(_) => "an array",
        JsonValue::Object(_) => "an object",
    }
}

fn condition_phrase(c: &fa_cli::verbs::Condition) -> String {
    match c {
        fa_cli::verbs::Condition::Always => "always".into(),
        fa_cli::verbs::Condition::Grant(op) => format!("`grant` includes `{op}`"),
        fa_cli::verbs::Condition::Voids => "the intent's `disposition` is `voids`".into(),
        fa_cli::verbs::Condition::ExistingCells => {
            "the period already has materialized register cells".into()
        }
    }
}

/// `--as-known-at` → `--as-known-at HEAD`: the flag's fragment of the usage text.
fn flag_hint(flag: &str, usage: &str) -> String {
    let Some(at) = usage.find(flag) else {
        return "see usage".into();
    };
    let tail = &usage[at..];
    let end = tail.find([')', ']', '|']).unwrap_or(tail.len());
    let frag = tail[..end].trim();
    frag.split(" --").next().unwrap_or(frag).trim().to_string()
}

/// `tb ((--period <code>)... | --fiscal-year N) [--activity]` → a runnable-ish
/// line: the first alternative of each group, the brackets dropped.
fn strip_usage_decoration(u: &str) -> String {
    let mut out = String::new();
    let mut chars = u.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '(' | ')' | '[' | ']' => {}
            '|' => {
                // Skip the alternative up to the group's close.
                while let Some(&n) = chars.peek() {
                    if n == ')' || n == ']' {
                        break;
                    }
                    chars.next();
                }
            }
            '.' if chars.peek() == Some(&'.') => {
                chars.next();
                chars.next();
            }
            c => out.push(c),
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Split a command line the way a shell would for double and single quotes
/// and backslashes; good enough for the registry's own examples and fixes.
#[must_use]
pub fn shell_split(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                in_word = true;
            }
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    in_word = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embedded() -> (McpRegistry, &'static Registry) {
        let reg = fa_cli::verbs::registry().expect("verbs.toml");
        (McpRegistry::embedded().expect("[mcp]"), reg)
    }

    #[test]
    fn the_embedded_mcp_section_is_valid_and_maps_every_verb() {
        let (mcp, reg) = embedded();
        assert_eq!(mcp.server, "fa-mcp");
        assert_eq!(mcp.max_tools_per_cluster, 7);
        for c in &mcp.clusters {
            assert!(mcp.tools_of(&c.name).count() <= 7, "{}", c.name);
        }
        for v in &reg.verbs {
            if v.subcommands.is_empty() {
                assert!(mcp.tool_for(&v.name, None).is_some(), "{}", v.name);
            } else {
                for s in &v.subcommands {
                    assert!(mcp.tool_for(&v.name, Some(s)).is_some(), "{} {s}", v.name);
                }
            }
        }
        let names: BTreeSet<String> = mcp.tools.iter().map(ToolSpec::wire_name).collect();
        assert_eq!(names.len(), mcp.tools.len());
        for n in &names {
            assert!(
                n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "{n}"
            );
        }
        assert!(names.contains("fa_orient_capabilities"));
        assert!(names.contains("fa_read_trial_balance"));
    }

    fn with(edit: impl Fn(&str) -> String) -> Result<McpRegistry, String> {
        let text = edit(SOURCE);
        let reg = Registry::parse(&text)?;
        McpRegistry::parse(&text, &reg)
    }

    #[test]
    fn inconsistent_mcp_sections_are_refused() {
        let cases: Vec<(&str, Result<McpRegistry, String>)> = vec![
            (
                "a tool naming an unknown verb",
                with(|s| s.replace("verb = \"tb\"", "verb = \"tbx\"")),
            ),
            (
                "a tool naming an unknown subcommand",
                with(|s| {
                    s.replace(
                        "verb = \"entry\"\nsubcommands = [\"show\"]",
                        "verb = \"entry\"\nsubcommands = [\"shows\"]",
                    )
                }),
            ),
            (
                "a verb neither a tool nor excluded",
                with(|s| {
                    s.replace("[[mcp.tool]]\ncluster = \"fa.read\"\nname = \"open_items\"\nverb = \"open-items\"", "[[mcp.tool]]\ncluster = \"fa.read\"\nname = \"open_items\"\nverb = \"tb\"")
                }),
            ),
            (
                "a verb both a tool and excluded",
                with(|s| {
                    s.replace(
                        "[[mcp.excluded]]\nverb = \"fad\"\nsubcommand = \"stop\"",
                        "[[mcp.excluded]]\nverb = \"tb\"",
                    )
                }),
            ),
            (
                "a cluster over the limit",
                with(|s| s.replace("max_tools_per_cluster = 7", "max_tools_per_cluster = 4")),
            ),
            (
                "a tool covered twice",
                with(|s| {
                    s.replace("name = \"period_status\"\nverb = \"period\"\nsubcommands = [\"list\"]", "name = \"period_status\"\nverb = \"period\"\nsubcommands = [\"list\", \"create\"]\nselector = \"which\"")
                }),
            ),
            (
                "an exclusion without a reason",
                with(|s| {
                    s.replace("reason = \"host-only: stops the daemon process that will host fa-mcp (plan §15.4 registered exclusion)\"", "reason = \"\"")
                }),
            ),
            (
                "a selector on a single subcommand",
                with(|s| {
                    s.replace("subcommands = [\"create\"]\npositionals = []\nflags = [\"--fiscal-year\"]", "subcommands = [\"create\"]\nselector = \"x\"\npositionals = []\nflags = [\"--fiscal-year\"]")
                }),
            ),
            (
                "a required name that is nothing",
                with(|s| {
                    s.replace(
                        "required = [\"--period\", \"account\"]",
                        "required = [\"--period\", \"acount\"]",
                    )
                }),
            ),
            (
                "a reserved property name",
                with(|s| s.replace("positionals = [\"vid\"]", "positionals = [\"book\"]")),
            ),
        ];
        for (what, result) in cases {
            assert!(result.is_err(), "{what} was accepted");
        }
        assert!(
            with(|s| s.to_string()).is_ok(),
            "the unedited source parses"
        );
    }

    #[test]
    fn wire_names_schemas_and_docs_derive_from_the_registry() {
        let (mcp, reg) = embedded();
        let tb = mcp.tool_by_wire("fa_read_trial_balance").expect("tb tool");
        let schema = tb.input_schema(&mcp, reg);
        let props = schema["properties"].as_object().expect("properties");
        for p in [
            "period",
            "fiscal_year",
            "as_of",
            "as_known_at",
            "activity",
            "book",
            "as",
            "keys",
        ] {
            assert!(props.contains_key(p), "{p}");
        }
        assert!(!props.contains_key("yes"), "tb is not dangerous");
        assert_eq!(props["period"]["type"], json!(["string", "array"]));
        assert_eq!(props["fiscal_year"]["type"], json!(["string", "integer"]));
        assert_eq!(props["activity"]["type"], json!("boolean"));
        assert_eq!(schema["additionalProperties"], json!(false));
        let doc = tb.description(&mcp, reg);
        for section in [
            "Do:",
            "Don't:",
            "Discovery:",
            "Examples:",
            "Common mistakes:",
            "Exits:",
        ] {
            assert!(doc.contains(section), "{section} missing in:\n{doc}");
        }
        assert!(
            doc.contains(
                "fa_read_trial_balance {\"book\":\"./books/myco\",\"period\":[\"FY2026-P03\"]}"
            ),
            "{doc}"
        );
        let period = mcp
            .tool_by_wire("fa_time_period_transition")
            .expect("period tool");
        let schema = period.input_schema(&mcp, reg);
        assert_eq!(
            schema["properties"]["transition"]["enum"],
            json!(["open", "soft-close", "close", "lock", "reopen"])
        );
        assert!(
            schema["properties"].get("yes").is_some(),
            "close/lock/reopen are dangerous"
        );
        assert!(
            schema["properties"].get("fiscal_year").is_none(),
            "narrowed flags"
        );
        let required = schema["required"].as_array().expect("required");
        assert!(required.contains(&json!("transition")) && required.contains(&json!("code")));
        let doc = period.description(&mcp, reg);
        assert!(
            doc.contains("soft-close"),
            "the dangerous rows' safe alternatives:\n{doc}"
        );
        let post = mcp.tool_by_wire("fa_post_post").expect("post tool");
        let schema = post.input_schema(&mcp, reg);
        assert_eq!(schema["properties"]["intent"]["type"], json!("object"));
        assert_eq!(schema["properties"]["intent_file"]["type"], json!("string"));
        assert_eq!(
            schema["properties"]["grant"]["type"],
            json!(["string", "array"])
        );
        assert!(
            schema["properties"].get("yes").is_some(),
            "grant:post_closed is dangerous"
        );
    }

    #[test]
    fn commands_become_tool_calls_and_back() {
        let (mcp, reg) = embedded();
        let call = mcp
            .command_to_call(reg, "fa period soft-close FY2026-P03 --book ./b --json")
            .expect("a call");
        assert_eq!(call.tool, "fa_time_period_transition");
        assert_eq!(
            call.arguments,
            json!({"transition": "soft-close", "code": "FY2026-P03", "book": "./b"})
        );
        let call = mcp
            .command_to_call(reg, "fa trial-balance --period P1 --period P2 --activity")
            .expect("alias");
        assert_eq!(call.tool, "fa_read_trial_balance");
        assert_eq!(
            call.arguments,
            json!({"period": ["P1", "P2"], "activity": true})
        );
        let call = mcp
            .command_to_call(reg, "fa post --intent entry.json --evidence ab --yes")
            .expect("post");
        assert_eq!(
            call.arguments,
            json!({"intent_file": "entry.json", "evidence": ["ab"], "yes": true})
        );
        assert!(mcp.command_to_call(reg, "fad status --book ./b").is_none());
        assert!(
            mcp.command_to_call(reg, "leave the period Closed")
                .is_none()
        );
        let calls = mcp.calls_in_text(
            reg,
            "`fa period soft-close <code>` stops ordinary postings; see `fa period list --json`",
        );
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].tool, "fa_time_period_status");
        // Round trip: the call's invocation is the command's argv (plus --json, without --book's dir order).
        let tool = mcp.tool_by_wire("fa_time_period_transition").expect("tool");
        let inv = tool
            .invocation(
                &mcp,
                reg,
                &json!({"transition": "soft-close", "code": "FY2026-P03", "book": "./b"}),
                None,
            )
            .expect("invocation");
        assert_eq!(
            inv.argv,
            vec![
                "period",
                "soft-close",
                "FY2026-P03",
                "--book",
                "./b",
                "--json"
            ]
        );
        assert_eq!(inv.stdin, None);
    }

    #[test]
    fn certificate_tools_accept_a_retained_file_or_inline_bytes() {
        let (mcp, reg) = embedded();
        for (wire, prefix) in [
            ("fa_read_replay", vec!["replay"]),
            ("fa_read_certificate_status", vec!["certificate", "status"]),
        ] {
            let tool = mcp.tool_by_wire(wire).expect("certificate tool");
            let schema = tool.input_schema(&mcp, reg);
            assert_eq!(schema["properties"]["certificate"]["type"], json!("string"));
            assert_eq!(schema["properties"]["file"]["type"], json!("string"));
            assert!(
                !schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("file")),
                "a host must accept inline bytes without a file: {schema}"
            );
            let inline = tool
                .invocation(&mcp, reg, &json!({"certificate": "abcd"}), Some("/b"))
                .expect("inline bytes");
            let mut expected = prefix.clone();
            expected.extend(["-", "--book", "/b", "--json"]);
            assert_eq!(inline.argv, expected);
            assert_eq!(inline.stdin, Some(b"abcd".to_vec()));
            let file = tool
                .invocation(&mcp, reg, &json!({"file": "report.cert"}), Some("/b"))
                .expect("retained file");
            let mut expected = prefix;
            expected.extend(["report.cert", "--book", "/b", "--json"]);
            assert_eq!(file.argv, expected);
            assert!(file.stdin.is_none());
            for args in [
                json!({}),
                json!({"file": "report.cert", "certificate": "abcd"}),
            ] {
                assert!(tool.invocation(&mcp, reg, &args, Some("/b")).is_err());
            }
        }
    }

    #[test]
    fn arguments_map_to_argv_with_stdin_forwarding_and_usage_errors() {
        let (mcp, reg) = embedded();
        let post = mcp.tool_by_wire("fa_post_post").expect("post");
        let inv = post
            .invocation(&mcp, reg, &json!({"intent": {"idempotency_key": "k", "legs": []}, "grant": "post_closed", "yes": true}), Some("/b"))
            .expect("ok");
        assert_eq!(
            inv.argv,
            vec![
                "post",
                "--intent",
                "-",
                "--grant",
                "post_closed",
                "--yes",
                "--book",
                "/b",
                "--json"
            ]
        );
        let stdin = String::from_utf8(inv.stdin.expect("stdin")).unwrap();
        assert!(stdin.contains("\"idempotency_key\":\"k\""));
        let inv = post
            .invocation(&mcp, reg, &json!({"intent_file": "e.json"}), Some("/b"))
            .expect("path form");
        assert_eq!(
            inv.argv,
            vec!["post", "--intent", "e.json", "--book", "/b", "--json"]
        );
        assert!(inv.stdin.is_none());
        for (what, args) in [
            (
                "both inline and path",
                json!({"intent": {}, "intent_file": "e.json"}),
            ),
            (
                "an unknown argument",
                json!({"intent": {}, "evidnce": ["x"]}),
            ),
            ("a non-object intent", json!({"intent": "entry.json"})),
            ("a non-boolean yes", json!({"intent": {}, "yes": "true"})),
            (
                "a number in a repeat flag",
                json!({"intent": {}, "evidence": [1]}),
            ),
        ] {
            assert!(
                post.invocation(&mcp, reg, &args, Some("/b")).is_err(),
                "{what}"
            );
        }
        let e = post
            .invocation(&mcp, reg, &json!({"intent": {}, "evidnce": ["x"]}), None)
            .unwrap_err();
        assert!(e.fix.contains("evidence"), "{e:?}");
        let explain = mcp
            .tool_by_wire("fa_read_explain_balance")
            .expect("explain");
        let e = explain
            .invocation(&mcp, reg, &json!({"period": "P"}), Some("/b"))
            .unwrap_err();
        assert!(e.message.contains("`account` is required"), "{e:?}");
        let inv = explain
            .invocation(
                &mcp,
                reg,
                &json!({"period": "P", "account": "1000"}),
                Some("/b"),
            )
            .expect("ok");
        assert_eq!(
            inv.argv,
            vec![
                "explain", "balance", "1000", "--period", "P", "--book", "/b", "--json"
            ]
        );
        let docs = mcp.tool_by_wire("fa_orient_robot_docs").expect("docs");
        let inv = docs
            .invocation(
                &mcp,
                reg,
                &json!({"topic": "schema", "name": "posted"}),
                None,
            )
            .expect("ok");
        assert_eq!(inv.argv, vec!["robot-docs", "schema", "posted", "--json"]);
        let e = docs
            .invocation(&mcp, reg, &json!({"topic": "shema"}), None)
            .unwrap_err();
        assert!(e.fix.contains("schema"), "{e:?}");
        let chart = mcp.tool_by_wire("fa_chart_import_chart").expect("chart");
        let inv = chart
            .invocation(
                &mcp,
                reg,
                &json!({"chart": {"accounts": []}, "book": "/b"}),
                None,
            )
            .expect("ok");
        assert_eq!(
            inv.argv,
            vec!["chart", "import", "-", "--book", "/b", "--json"]
        );
        let fy = mcp.tool_by_wire("fa_time_create_periods").expect("periods");
        let inv = fy
            .invocation(&mcp, reg, &json!({"fiscal_year": 2026}), Some("/b"))
            .expect("integer flag");
        assert_eq!(
            inv.argv,
            vec![
                "period",
                "create",
                "--fiscal-year",
                "2026",
                "--book",
                "/b",
                "--json"
            ]
        );
    }

    #[test]
    fn shell_split_handles_quotes() {
        assert_eq!(
            shell_split(r#"fa book create --name "My Co" --book ./books/myco --json"#),
            vec![
                "fa",
                "book",
                "create",
                "--name",
                "My Co",
                "--book",
                "./books/myco",
                "--json"
            ]
        );
        assert_eq!(shell_split("a 'b c' d\\ e"), vec!["a", "b c", "d e"]);
        assert_eq!(
            strip_usage_decoration(
                "tb ((--period <code>)... | --fiscal-year N) [--activity] [--as-known-at HEAD|<seq>]"
            ),
            "tb --period <code> --activity --as-known-at HEAD"
        );
    }

    #[test]
    fn projection_verification_is_a_read_only_target_with_a_cli_round_trip() {
        let (mcp, reg) = embedded();
        let tool = mcp
            .tool_for("verify", Some("projections"))
            .expect("projection verifier target");
        assert_eq!(tool.wire_name(), "fa_book_verify");
        assert!(!reg.verb("verify").unwrap().writes);
        assert!(!tool.is_dangerous(reg));
        let schema = tool.input_schema(&mcp, reg);
        assert!(
            schema["properties"]["target"]["enum"]
                .as_array()
                .unwrap()
                .contains(&json!("projections"))
        );
        let invocation = tool
            .invocation(&mcp, reg, &json!({"target": "projections"}), Some("/b"))
            .expect("read-only verification");
        assert_eq!(
            invocation.argv,
            vec!["verify", "projections", "--book", "/b", "--json"]
        );
        assert!(invocation.stdin.is_none());
        let call = mcp
            .command_to_call(reg, "fa verify projections --book /b --json")
            .expect("projection verification tool call");
        assert_eq!(call.tool, "fa_book_verify");
        assert_eq!(
            call.arguments,
            json!({"target": "projections", "book": "/b"})
        );
    }

}
