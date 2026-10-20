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
//! - [`dispatch`] runs every call through [`fa_cli::entry::fa_with_authority`]
//!   under one principal, profile, capability and book fixed at trusted launch.
//!   The accounting handlers and kernel are shared with the CLI, while the
//!   bound entrypoint refuses unauthenticated daemon forwarding;
//! - [`errors`] maps the envelope's one `error` event into the structured
//!   error `{type, message, recoverable, fix_hint, suggested_tool_calls, …}`:
//!   the exit class is the type, the refusal's `fix` the hint, and every
//!   `fa …` command that needs no caller authority override becomes a tool call;
//! - [`detect`] runs the mistake detectors before anything is dispatched:
//!   a JSON number where an amount string is required, an instant where a
//!   civil date is required, a posting leg on a summary account, an intent
//!   re-dated after a period-law refusal (never a suggestion to re-date), a
//!   self-approval, and placeholder text;
//! - [`server`] wires the tools, the 4 workflow macros (`fa.macro.prepare_close`,
//!   `fa.macro.record_and_match_cash`, `fa.macro.investigate_account`,
//!   `fa.macro.produce_audit_package`), and the 13 resources (`resource://fa/book`,
//!   `resource://fa/chart/{book}`, `resource://fa/periods/{book}`,
//!   `resource://fa/laws`, `resource://fa/exit-codes`, `resource://fa/intents`,
//!   `resource://fa/open-items/{book}/{party}`, `resource://fa/findings/{book}`,
//!   `resource://fa/cases/{book}`, `resource://fa/drafts/{book}`,
//!   `resource://fa/certificates/{id}`, `resource://fa/bundles/{id}`,
//!   `resource://fa/capabilities/{token}`)
//!   into a fastmcp server; the `fa-mcp` binary serves it over stdio.
//!
//! A successful call returns the robot envelope's `data` as the first text
//! content block (canonical JSON, exactly the bytes `fa --json` prints under
//! `data`) and the rest of the envelope — book, coordinate, certificate,
//! warnings, next actions as tool calls, and launch authority — as the second.
//! A failure is a tool error (`isError`) whose text is the structured error,
//! also labelled with the launch authority. Resource data remains first;
//! its second JSON content block identifies the same authority.
//! The transport is MCP 2026-07-28: use `server/discover` and include protocol
//! version and client capabilities in every request's `_meta`. Legacy
//! `initialize` negotiation is refused, so resource errors retain their
//! structured `data`, including the launch authority.
//!
//! # No-claim boundary
//!
//! This crate proves parity of the exposed verbs with the CLI (the parity
//! test: every verb and subcommand is a tool in exactly one cluster or a
//! registered exclusion) and the error contract (the mapping from the
//! envelope's `error` event, with planted refusals). It does not prove MCP
//! conformance beyond what fastmcp's own suite proves, and it is not yet
//! hosted by `fad`: the binary is a sibling of `fa` that takes the book's
//! writer lease and refuses when another process holds it. Launch configuration
//! is trusted operator input, not authenticated capability issuance or a
//! filesystem sandbox. Agent is the default profile and its accounting writes
//! to trunk reach the kernel's FA-REF-013. The explicitly selected Preparer
//! template permits ordinary posting. Both templates have bounded operations;
//! neither accepts per-call identity, grants, book/key selection or dangerous
//! confirmation. Authenticated daemon sessions and separate dangerous-operation
//! confirmation remain follow-ups.

#![forbid(unsafe_code)]

pub mod detect;
pub mod dispatch;
pub mod errors;
pub mod registry;
pub mod server;

/// This build's version, as `fa capabilities` reports it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
