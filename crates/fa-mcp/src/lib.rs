//! `fa-mcp` — the FrankenAccounting MCP server (plan §1 posture (c), §2.4,
//! §15.4, Appendix D; bead fa-xex).
//!
//! A thin adapter from the verb registry (`registries/verbs.toml`, the single
//! source of the `fa` CLI, the `fad` daemon and this server) to fastmcp
//! tools. It defines no accounting semantics of its own:
//!
//! - [`registry`] reads the registry's `[mcp]` section — the tool clusters
//!   (at most seven tools each), the registered exclusions, and each tool's
//!   positionals — and derives every tool's wire name, JSON input schema and
//!   Do / Don't / Discovery / Examples / Common-mistakes documentation from
//!   the verb rows, the `[[dangerous]]` rows and the `[[next_action]]` rows;
//! - [`dispatch`] runs every tool call through the same front door the `fa`
//!   binary uses ([`fa_cli::entry::fa_with`]): directly under the book's
//!   writer lease, or through the `fad` that holds it. A refusal is therefore
//!   byte-identical whichever surface asked;
//! - [`errors`] maps the envelope's one `error` event into the structured
//!   error `{type, message, recoverable, fix_hint, suggested_tool_calls, …}`:
//!   the exit class is the type, the refusal's `fix` the hint, and every
//!   `fa …` command the fix or the catalog names becomes a tool call;
//! - [`detect`] runs the mistake detectors before anything is dispatched:
//!   a JSON number where an amount string is required, an instant where a
//!   civil date is required, a posting leg on a summary account, an intent
//!   re-dated after a period-law refusal (never a suggestion to re-date), a
//!   self-approval, and placeholder text;
//! - [`server`] wires the tools and the resources (`resource://fa/book`,
//!   `resource://fa/chart/{book}`, `resource://fa/periods/{book}`,
//!   `resource://fa/laws`, `resource://fa/exit-codes`, `resource://fa/intents`)
//!   into a fastmcp server; the `fa-mcp` binary serves it over stdio.
//!
//! A successful call returns the robot envelope's `data` as the first text
//! content block (canonical JSON, exactly the bytes `fa --json` prints under
//! `data`) and the rest of the envelope — book, coordinate, certificate,
//! warnings, next actions as tool calls — as the second. A failure is a tool
//! error (`isError`) whose text is the structured error.
//!
//! # No-claim boundary
//!
//! This crate proves parity of the exposed verbs with the CLI (the parity
//! test: every verb and subcommand is a tool in exactly one cluster or a
//! registered exclusion) and the error contract (the mapping from the
//! envelope's `error` event, with planted refusals). It does not prove MCP
//! conformance beyond what fastmcp's own suite proves, and it is not yet
//! hosted by `fad`: the binary is a sibling of `fa` that runs each call under
//! the book's writer lease or through the book's daemon, exactly as `fa`
//! does. Hosting the server inside `fad` (one open book, one lease, plan
//! §15.4) is a follow-up.

#![forbid(unsafe_code)]

pub mod detect;
pub mod dispatch;
pub mod errors;
pub mod registry;
pub mod server;

/// This build's version, as `fa capabilities` reports it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
