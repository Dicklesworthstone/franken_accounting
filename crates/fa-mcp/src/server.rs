//! The fastmcp server: one [`ToolHandler`] per registry tool, one
//! [`ResourceHandler`] per resource, all over one [`Adapter`] that runs the
//! detectors, maps arguments to argv, dispatches through the front door and
//! maps the reply.
//!
//! Every tool handler is synchronous and blocking (the book's one writer,
//! one call at a time); fastmcp runs it off the transport's driver thread.
//! The adapter keeps the session's [`Memory`] for the detectors that need
//! what this session has seen.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::json::Json;
use fa_cli::verbs::Registry;
use fastmcp_rust::auto::{Server, ServerBuilder};
use fastmcp_rust::server::{ResourceHandler, ToolHandler, UriParams};
use fastmcp_rust::{
    Content, JsonValue, McpContext, McpError, McpErrorCode, McpResult, Resource, ResourceContent,
    ResourceTemplate, Tool, ToolAnnotations, json,
};

use crate::detect::{self, Memory};
use crate::dispatch::{self, Reply, to_wire};
use crate::errors::StructuredError;
use crate::registry::{Invocation, McpRegistry, RESOURCES, ToolSpec};

/// The law registries `resource://fa/laws` serves verbatim (the TOML the
/// kernel embeds; the same bytes).
pub const LAWS: &[(&str, &str)] = &[
    (
        "entry_classes.toml",
        include_str!("../../../registries/entry_classes.toml"),
    ),
    (
        "admissibility.toml",
        include_str!("../../../registries/admissibility.toml"),
    ),
    (
        "rounding_laws.toml",
        include_str!("../../../registries/rounding_laws.toml"),
    ),
    ("units.toml", include_str!("../../../registries/units.toml")),
    (
        "evidence_policy.toml",
        include_str!("../../../registries/evidence_policy.toml"),
    ),
    (
        "sod_policy.toml",
        include_str!("../../../registries/sod_policy.toml"),
    ),
    (
        "reason_codes.toml",
        include_str!("../../../registries/reason_codes.toml"),
    ),
    (
        "refusal_catalog.toml",
        include_str!("../../../registries/refusal_catalog.toml"),
    ),
    (
        "account_types.toml",
        include_str!("../../../registries/account_types.toml"),
    ),
    (
        "limits.toml",
        include_str!("../../../registries/limits.toml"),
    ),
];

/// What the server was started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// The fixed book for every tool call and resource read.
    pub book: Option<PathBuf>,
    /// The fixed key file; never supplied by a tool call.
    pub keys: Option<PathBuf>,
    /// The operator-selected principal, fixed for the session.
    pub principal: String,
    pub profile: LaunchProfile,
    /// Explicit operations attenuate the selected launch profile's ceiling.
    pub grants: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            book: None,
            keys: None,
            principal: "mcp-agent".into(),
            profile: LaunchProfile::Agent,
            grants: Vec::new(),
        }
    }
}

/// A rejected launch configuration is distinct from an embedded registry defect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerError {
    Launch(String),
    Foundation(String),
}

impl ServerError {
    #[must_use]
    pub const fn exit(&self) -> u8 {
        match self {
            Self::Launch(_) => 7,
            Self::Foundation(_) => 5,
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Launch(message) | Self::Foundation(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ServerError {}

/// The result of a successful call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallOutput {
    /// The envelope's `data`, canonical JSON (one object; an array when the
    /// verb emitted several lines).
    pub data: String,
    /// The rest of the envelope: events, book, coordinate, certificate,
    /// warnings, next actions as tool calls.
    pub envelope: JsonValue,
}

/// The adapter every handler shares.
pub struct Adapter {
    pub mcp: McpRegistry,
    pub reg: &'static Registry,
    pub authority: LaunchAuthority,
    memory: Mutex<Memory>,
}

// The error of every fallible step is the structured error itself (plan
// §15.4's `{type, message, recoverable, fix_hint, suggested_tool_calls, …}`),
// built once per refusal on no hot path; boxing it would buy nothing.
#[allow(clippy::result_large_err)]
impl Adapter {
    pub fn new(config: ServerConfig) -> Result<Self, ServerError> {
        let book = config.book.ok_or_else(|| {
            ServerError::Launch("a fixed book is required; launch with --book or FA_BOOK".into())
        })?;
        let grants: Vec<&str> = config.grants.iter().map(String::as_str).collect();
        let authority =
            LaunchAuthority::new(book, config.keys, config.principal, config.profile, &grants)
                .map_err(ServerError::Launch)?;
        let reg = fa_cli::verbs::registry()
            .map_err(|e| ServerError::Foundation(format!("the embedded verb registry: {e}")))?;
        let mcp =
            McpRegistry::parse(crate::registry::SOURCE, reg).map_err(ServerError::Foundation)?;
        Ok(Self {
            mcp,
            reg,
            authority,
            memory: Mutex::new(Memory::default()),
        })
    }

    fn authority_json(&self) -> JsonValue {
        to_wire(&self.authority.envelope_json())
    }

    fn dispatch(&self, inv: &Invocation) -> Result<Reply, StructuredError> {
        dispatch::run(self.reg, inv, &self.authority).map_err(StructuredError::foundation)
    }

    /// Run a read-only verb (no arguments beyond the book) and return its
    /// one line's `data`.
    fn read(&self, argv: &[&str]) -> Result<Json, StructuredError> {
        let mut inv = Invocation {
            argv: argv.iter().map(|a| (*a).to_string()).collect(),
            stdin: None,
        };
        inv.argv.push("--json".into());
        let reply = self.dispatch(&inv)?;
        if reply.exit != 0 {
            return Err(self.error_of(&reply));
        }
        reply
            .lines
            .into_iter()
            .next()
            .map(|l| l.data)
            .ok_or_else(|| {
                StructuredError::foundation("the dispatcher exited 0 without a robot line")
            })
    }

    fn error_of(&self, reply: &Reply) -> StructuredError {
        match reply.error() {
            Some(line) => StructuredError::from_error_event(&self.mcp, self.reg, &line.data),
            None => StructuredError::foundation(format!(
                "the dispatcher exited {} without an error event; stderr: {}",
                reply.exit,
                reply.stderr.trim()
            )),
        }
    }

    /// One tool call: detectors, mapping, dispatch, mapping back.
    pub fn call(
        &self,
        tool: &ToolSpec,
        arguments: &JsonValue,
    ) -> Result<CallOutput, StructuredError> {
        self.call_inner(tool, arguments)
            .map_err(|e| e.with_authority(self.authority_json()))
    }

    fn call_inner(
        &self,
        tool: &ToolSpec,
        arguments: &JsonValue,
    ) -> Result<CallOutput, StructuredError> {
        if let Some(argument) = crate::registry::forbidden_argument(arguments) {
            return Err(StructuredError::forbidden_argument(argument));
        }
        if let Some((argument, fix)) = tool.forbidden_path_argument(arguments) {
            return Err(StructuredError::forbidden_path(&argument, fix));
        }
        if let Some(e) = detect::floats(arguments)
            .or_else(|| detect::instants(tool, arguments))
            .or_else(|| detect::placeholders(tool, arguments))
        {
            return Err(e);
        }
        let inv = tool
            .invocation(&self.mcp, self.reg, arguments)
            .map_err(|e| StructuredError::arguments(e.message, e.fix))?;
        if detect::intent_of(tool, arguments).is_some() {
            // The chart is read through the same front door; when the book
            // cannot be read, the dispatch below reports why.
            if let Ok(chart) = self.read(&["chart", "list"])
                && let Some(e) = detect::summary_account(tool, arguments, &chart)
            {
                return Err(e);
            }
        }
        {
            let memory = self
                .memory
                .lock()
                .map_err(|_| StructuredError::foundation("the session memory is poisoned"))?;
            if let Some(e) = detect::redated_intent(tool, arguments, &memory).or_else(|| {
                detect::self_approval(tool, arguments, &memory, self.authority.principal())
            }) {
                return Err(e);
            }
        }
        let reply = self.dispatch(&inv)?;
        if let Ok(mut memory) = self.memory.lock() {
            detect::remember(
                &mut memory,
                tool,
                arguments,
                &reply,
                self.authority.principal(),
            );
        }
        if reply.exit != 0 {
            return Err(self.error_of(&reply));
        }
        let Some(last) = reply.lines.last() else {
            return Err(StructuredError::foundation(
                "the dispatcher exited 0 without a robot line",
            ));
        };
        let data = match reply.lines.as_slice() {
            [one] => one.data.render(),
            many => Json::Arr(many.iter().map(|l| l.data.clone()).collect()).render(),
        };
        let next_actions: Vec<JsonValue> = last
            .line
            .get("next_actions")
            .and_then(Json::as_arr)
            .map(|items| {
                items
                    .iter()
                    .map(|n| {
                        let command = n.get("command").and_then(Json::as_str).unwrap_or("");
                        let mut v = to_wire(n);
                        if let Some(call) = self.mcp.command_to_call(self.reg, command) {
                            v["call"] = json!({ "tool": call.tool, "arguments": call.arguments });
                        }
                        v
                    })
                    .collect()
            })
            .unwrap_or_default();
        let field = |k: &str| last.line.get(k).map_or(JsonValue::Null, to_wire);
        let envelope = json!({
            "events": reply.lines.iter().map(|l| l.event.clone()).collect::<Vec<_>>(),
            "book": field("book"),
            "coordinate": field("coordinate"),
            "certificate": field("certificate"),
            "warnings": field("warnings"),
            "next_actions": next_actions,
            "stderr": reply.stderr,
            "authority": self.authority_json(),
        });
        Ok(CallOutput { data, envelope })
    }

    /// One resource read: the MIME type and the text.
    pub fn read_resource(
        &self,
        template: &str,
        params: &UriParams,
    ) -> Result<(String, String), StructuredError> {
        self.read_resource_inner(template, params)
            .map_err(|e| e.with_authority(self.authority_json()))
    }

    fn read_resource_inner(
        &self,
        template: &str,
        params: &UriParams,
    ) -> Result<(String, String), StructuredError> {
        let json_mime = "application/json".to_string();
        if let Some(book) = params.get("book").map(String::as_str).map(percent_decode)
            && book != "default"
            && Path::new(&book) != self.authority.book()
        {
            return Err(StructuredError::forbidden_argument("book"));
        }
        match template {
            "resource://fa/book" => Ok((json_mime, self.read(&["book", "info"])?.render())),
            "resource://fa/chart/{book}" => {
                Ok((json_mime, self.read(&["chart", "list"])?.render()))
            }
            "resource://fa/periods/{book}" => {
                Ok((json_mime, self.read(&["period", "list"])?.render()))
            }
            "resource://fa/laws" => {
                let mut m = fastmcp_rust::JsonMap::new();
                for (name, text) in LAWS {
                    m.insert((*name).to_string(), JsonValue::String((*text).to_string()));
                }
                Ok((json_mime, JsonValue::Object(m).to_string()))
            }
            "resource://fa/exit-codes" => {
                let caps = self.read(&["capabilities"])?;
                Ok((
                    json_mime,
                    caps.get("exit_codes")
                        .cloned()
                        .unwrap_or(Json::Null)
                        .render(),
                ))
            }
            "resource://fa/intents" => {
                let caps = self.read(&["capabilities"])?;
                let examples = self.read(&["robot-docs", "examples"])?;
                let tools: Vec<String> = self
                    .mcp
                    .tools
                    .iter()
                    .filter(|t| detect::intent_of(t, &json!({"intent": {}})).is_some())
                    .map(ToolSpec::wire_name)
                    .collect();
                let v = json!({
                    "entry_classes": caps.get("entry_classes").map_or(JsonValue::Null, to_wire),
                    "examples": examples.get("text").map_or(JsonValue::Null, to_wire),
                    "tools": tools,
                    "schema": JsonValue::Null,
                    "planning": {
                        "dry_run": "Set dry_run=true on a posting tool to run the actual laws without publishing. A bounded Preparer session can review the plan event and pass its complete bytes hex string as plan to fa_post_commit_plan under the same launch principal and capability.",
                        "period_transition": "Set dry_run=true on fa_time_period_transition to receive existing canonical TransitionPlan bytes inline. This prepares a sealed period-transition proposal; commit independently checks authority, approvals and current period state. It is not a PostEntry effects certificate, and dangerous MCP commits remain unavailable.",
                        "files": "Caller filesystem paths are refused. Supply content inline; no --files root is supported.",
                        "scope": "same-snapshot-post",
                        "invalidation": "Any intervening publication before the first commit requires another dry run. This slice preserves supplied approvals; it does not gather new approvals, create drafts, or rehearse balancing.",
                        "authority": "The artifact grants no authority. The default Agent profile cannot plan or commit accounting entries to trunk. Tool calls cannot select another principal, profile, book or grants. Dangerous void plan commits remain unavailable until a separate confirmation exchange exists.",
                        "commit_tool": "fa_post_commit_plan",
                    },
                    "note": "the JSON intent document forms this build accepts, as the examples show them (an intent is the `intent` object of the tools listed); a machine-readable JSON intent schema is not registered yet. The fa-intents PostEntry artifact has a separate bounded canonical binary format, returned as complete hex bytes for MCP transport",
                });
                Ok((json_mime, v.to_string()))
            }
            other => Err(StructuredError::arguments(
                format!("no resource `{other}`"),
                format!(
                    "one of {}",
                    RESOURCES
                        .iter()
                        .map(|(u, _)| *u)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        }
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(high), Some(low)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(high * 16 + low);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One registry tool as a fastmcp tool.
pub struct VerbTool {
    adapter: Arc<Adapter>,
    spec: ToolSpec,
    definition: Tool,
}

impl VerbTool {
    #[must_use]
    pub fn new(adapter: Arc<Adapter>, spec: ToolSpec) -> Self {
        let reg = adapter.reg;
        let writes = reg.verb(&spec.verb).is_some_and(|v| v.writes);
        let definition = Tool {
            name: spec.wire_name(),
            description: Some(spec.description(&adapter.mcp, reg)),
            input_schema: spec.input_schema(&adapter.mcp, reg),
            output_schema: None,
            icon: None,
            version: Some(crate::VERSION.to_string()),
            tags: vec![spec.cluster.clone()],
            annotations: Some(ToolAnnotations {
                destructive: Some(spec.is_dangerous(reg)),
                idempotent: Some(!writes),
                read_only: Some(!writes),
                open_world_hint: Some(false),
            }),
        };
        Self {
            adapter,
            spec,
            definition,
        }
    }

    #[must_use]
    pub fn spec(&self) -> &ToolSpec {
        &self.spec
    }
}

impl ToolHandler for VerbTool {
    fn definition(&self) -> Tool {
        self.definition.clone()
    }

    fn annotations(&self) -> Option<&ToolAnnotations> {
        self.definition.annotations.as_ref()
    }

    fn tags(&self) -> &[String] {
        &self.definition.tags
    }

    fn call(&self, ctx: &McpContext, arguments: JsonValue) -> McpResult<Vec<Content>> {
        ctx.checkpoint()?;
        match self.adapter.call(&self.spec, &arguments) {
            Ok(out) => Ok(vec![
                Content::text(out.data),
                Content::text(out.envelope.to_string()),
            ]),
            // A tool error (`isError`): the structured error is its text.
            Err(e) => Err(McpError::tool_error(e.render())),
        }
    }
}

/// One registry resource as a fastmcp resource.
pub struct FaResource {
    adapter: Arc<Adapter>,
    uri: &'static str,
    doc: &'static str,
}

impl FaResource {
    #[must_use]
    pub fn new(adapter: Arc<Adapter>, uri: &'static str, doc: &'static str) -> Self {
        Self { adapter, uri, doc }
    }

    fn is_template(&self) -> bool {
        self.uri.contains('{')
    }

    fn name(&self) -> String {
        self.uri
            .trim_start_matches("resource://fa/")
            .replace("/{book}", "")
            .replace('/', "_")
    }
}

impl ResourceHandler for FaResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: self.uri.to_string(),
            name: self.name(),
            description: Some(self.doc.to_string()),
            mime_type: Some("application/json".into()),
            icon: None,
            version: Some(crate::VERSION.to_string()),
            tags: Vec::new(),
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        self.is_template().then(|| ResourceTemplate {
            uri_template: self.uri.to_string(),
            name: self.name(),
            description: Some(self.doc.to_string()),
            mime_type: Some("application/json".into()),
            icon: None,
            version: Some(crate::VERSION.to_string()),
            tags: Vec::new(),
        })
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        self.read_with_uri(ctx, self.uri, &HashMap::new())
    }

    fn read_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        ctx.checkpoint()?;
        match self.adapter.read_resource(self.uri, params) {
            Ok((mime, text)) => Ok(vec![
                ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some(mime),
                    text: Some(text),
                    blob: None,
                },
                ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("application/json".into()),
                    text: Some(json!({"authority": self.adapter.authority_json()}).to_string()),
                    blob: None,
                },
            ]),
            Err(e) => {
                let code = if e.exit == 4 {
                    McpErrorCode::ResourceNotFound
                } else {
                    McpErrorCode::ToolExecutionError
                };
                Err(McpError::with_data(code, e.message.clone(), e.to_json()))
            }
        }
    }
}

/// Build the server: every registry tool, every resource, the instructions.
pub fn build_server(config: ServerConfig) -> Result<Server, ServerError> {
    let adapter = Arc::new(Adapter::new(config)?);
    let instructions = format!(
        "{}\n\nThis session's trusted launch authority: {}",
        adapter.mcp.instructions(),
        adapter.authority_json(),
    );
    let mut builder =
        ServerBuilder::new(adapter.mcp.server.clone(), crate::VERSION).instructions(instructions);
    for spec in adapter.mcp.tools.clone() {
        builder = builder.tool(VerbTool::new(Arc::clone(&adapter), spec));
    }
    for (uri, doc) in RESOURCES {
        builder = builder.resource(FaResource::new(Arc::clone(&adapter), uri, doc));
    }
    builder
        .try_build()
        .map_err(|e| ServerError::Foundation(format!("fa-mcp could not register its tools: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ServerConfig {
        ServerConfig {
            book: Some(PathBuf::from("/nonexistent/book")),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn the_server_builds_with_every_tool_and_resource_registered() {
        let server = build_server(config());
        assert!(server.is_ok(), "{:?}", server.err());
        let adapter = Adapter::new(config()).expect("adapter");
        for spec in &adapter.mcp.tools {
            let tool = VerbTool::new(
                Arc::new(Adapter::new(config()).expect("adapter")),
                spec.clone(),
            );
            let d = tool.definition();
            assert_eq!(d.name, spec.wire_name());
            assert!(d.description.as_deref().is_some_and(|s| s.contains("Do:")));
            assert_eq!(d.input_schema["type"], json!("object"));
        }
    }

    #[test]
    fn bookless_discovery_uses_bound_authority_without_reading_the_book() {
        let adapter = Adapter::new(config()).expect("adapter");
        let caps = adapter
            .mcp
            .tool_by_wire("fa_orient_capabilities")
            .expect("tool")
            .clone();
        let out = adapter.call(&caps, &json!({})).expect("capabilities");
        let (exit, captured) = fa_cli::entry::fa_with_authority(
            &["capabilities".into(), "--json".into()],
            fa_cli::cli::Files::default(),
            &adapter.authority,
            true,
        );
        assert_eq!(exit, 0);
        let line = fa_cli::json::parse(captured.stdout.trim_end()).expect("a robot line");
        assert_eq!(
            out.data,
            line.get("data").expect("data").render(),
            "byte for byte"
        );
        assert_eq!(out.envelope["events"], json!(["capabilities"]));
        assert_eq!(out.envelope["book"], JsonValue::Null);
        assert_eq!(out.envelope["authority"], adapter.authority_json());
        let data = fa_cli::json::parse(&out.data).unwrap();
        assert_eq!(
            data.get("capability")
                .unwrap()
                .get("binding")
                .unwrap()
                .get("posture")
                .and_then(Json::as_str),
            Some("mcp-launch-config"),
        );
    }

    #[test]
    fn a_detected_mistake_and_a_dispatcher_refusal_are_both_structured() {
        let adapter = Adapter::new(config()).expect("adapter");
        let post = adapter
            .mcp
            .tool_by_wire("fa_post_post")
            .expect("tool")
            .clone();
        let e = adapter
            .call(&post, &json!({"intent": {"effective_date": "2026-03-15", "idempotency_key": "k", "legs": [{"side": "debit", "account": "6000", "amount": 1.5}]}}))
            .unwrap_err();
        assert_eq!(e.detector.as_deref(), Some("float_amount"));
        let tb = adapter
            .mcp
            .tool_by_wire("fa_read_trial_balance")
            .expect("tool")
            .clone();
        let e = adapter.call(&tb, &json!({"period": "P"})).unwrap_err();
        assert_eq!(e.detector, None);
        assert_eq!(e.exit, 4, "{e:?}");
        assert_eq!(e.kind, "environment");
        assert_eq!(e.authority, Some(adapter.authority_json()));
        assert!(!e.message.is_empty());
        let e = adapter
            .call(&tb, &json!({"period": "P", "activity": "yes"}))
            .unwrap_err();
        assert_eq!(e.detector.as_deref(), Some("arguments"));
    }

    #[test]
    fn resources_that_need_no_book_read_and_unknown_ones_refuse() {
        let adapter = Adapter::new(config()).expect("adapter");
        let (mime, text) = adapter
            .read_resource("resource://fa/exit-codes", &HashMap::new())
            .expect("exit codes");
        assert_eq!(mime, "application/json");
        assert!(text.contains("\"name\":\"safety\""), "{text}");
        let (_, laws) = adapter
            .read_resource("resource://fa/laws", &HashMap::new())
            .expect("laws");
        assert!(laws.contains("admissibility.toml") && laws.contains("sod_policy.toml"));
        let (_, intents) = adapter
            .read_resource("resource://fa/intents", &HashMap::new())
            .expect("intents");
        assert!(
            intents.contains("fa_post_post") && intents.contains("idempotency_key"),
            "{intents}"
        );
        assert!(
            adapter
                .read_resource("resource://fa/nothing", &HashMap::new())
                .is_err()
        );
        // A book resource on a book that does not exist is the dispatcher's
        // environment error, structured, never a panic or an empty answer.
        let params: UriParams =
            HashMap::from([("book".to_string(), "%2Fnonexistent%2Fbook".to_string())]);
        let e = adapter
            .read_resource("resource://fa/chart/{book}", &params)
            .unwrap_err();
        assert_eq!(e.exit, 4, "{e:?}");
        assert_eq!(e.kind, "environment");
        assert_eq!(percent_decode("%2Ftmp%2Fbook%20x"), "/tmp/book x");
        assert_eq!(percent_decode("plain"), "plain");
        for malformed in ["%€", "%💥", "%A€", "%", "%2", "%xz"] {
            assert_eq!(percent_decode(malformed), malformed);
            let params = HashMap::from([("book".into(), malformed.into())]);
            let error = adapter
                .read_resource("resource://fa/chart/{book}", &params)
                .expect_err("foreign book must refuse without a UTF-8 slice panic");
            assert_eq!(error.kind, "forbidden_argument");
            assert_eq!(error.authority, Some(adapter.authority_json()));
        }
    }

    #[test]
    fn forbidden_arguments_precede_detectors_and_resource_reads() {
        let adapter = Adapter::new(config()).expect("adapter");
        let post = adapter.mcp.tool_by_wire("fa_post_post").expect("post");
        for argument in crate::registry::FORBIDDEN_ARGUMENTS {
            for value in [JsonValue::Null, json!(false), json!("operator")] {
                let mut input = json!({"intent": {"amount": 1.25}});
                input[*argument] = value;
                let error = adapter.call(post, &input).expect_err("forbidden");
                let json = error.to_json();
                assert_eq!(json["type"], "forbidden_argument", "{json}");
                assert_eq!(json["data"]["argument"], *argument);
                assert_eq!(json["authority"], adapter.authority_json());
                assert!(json.get("detector").is_none());
            }
        }
        let params = HashMap::from([("book".into(), "%2Fanother%2Fbook".into())]);
        let error = adapter
            .read_resource("resource://fa/chart/{book}", &params)
            .expect_err("resource cannot change book");
        assert_eq!(error.kind, "forbidden_argument");
        assert_eq!(error.detail["argument"], "book");
        assert_eq!(error.authority, Some(adapter.authority_json()));
    }

    #[test]
    fn host_path_arguments_precede_detectors_and_all_dispatch() {
        let adapter = Adapter::new(config()).expect("adapter");
        for tool in &adapter.mcp.tools {
            let schema = tool.input_schema(&adapter.mcp, adapter.reg);
            let mut paths: Vec<String> = [
                "file",
                "intent_file",
                "plan_file",
                "plan_out",
                "certificate_out",
            ]
            .iter()
            .map(|path| (*path).to_string())
            .collect();
            if let Some(stdin) = &tool.stdin {
                paths.push(tool.via_property(stdin));
            }
            paths.sort();
            paths.dedup();
            for argument in paths {
                assert!(
                    schema["properties"].get(&argument).is_none(),
                    "{} exposes {argument}",
                    tool.wire_name()
                );
                for value in [
                    JsonValue::Null,
                    json!(false),
                    json!("/host/secret"),
                    json!("../outside"),
                    json!("symlink/target"),
                ] {
                    let mut input = json!({"intent": {"amount": 1.25}});
                    input[&argument] = value;
                    let error = adapter
                        .call(tool, &input)
                        .expect_err("host path refused before float/input checks or missing book");
                    let json = error.to_json();
                    assert_eq!(json["type"], "forbidden_path", "{json}");
                    assert_eq!(json["exit"], 2);
                    assert_eq!(json["data"]["argument"], argument);
                    assert_eq!(json["authority"], adapter.authority_json());
                    assert!(json.get("detector").is_none());
                    assert_eq!(json["suggested_tool_calls"], json!([]));
                    assert!(tool.invocation(&adapter.mcp, adapter.reg, &input).is_err());
                }
            }
        }
    }

    #[test]
    fn launch_requires_a_book_and_refuses_grants_outside_the_profile_ceiling() {
        let error = Adapter::new(ServerConfig::default())
            .err()
            .expect("book required");
        assert_eq!(error.exit(), 7);
        for profile in [LaunchProfile::Agent, LaunchProfile::Preparer] {
            for grant in ["approve", "close", "post_closed", "migrate", "witness"] {
                let error = Adapter::new(ServerConfig {
                    profile,
                    grants: vec![grant.into()],
                    ..config()
                })
                .err()
                .expect("grant exceeds launch ceiling");
                assert_eq!(error.exit(), 7, "{error}");
            }
        }
    }
}
