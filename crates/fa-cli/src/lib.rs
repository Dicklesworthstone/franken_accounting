//! The `fa` command set as a library, shared by the `fa` binary and the
//! `fad` daemon (plan §15.3, Appendix D):
//!
//! - [`verbs`]: the verb registry (`registries/verbs.toml`) that drives
//!   dispatch, flags, help, the robot-mode schema, and the daemon contract;
//! - [`cli`]: the registry-driven dispatcher and every command, writing to a
//!   stdio or captured sink against a directory book or a daemon's held book;
//! - [`entry`]: the `fa` front door (direct under the writer lease, or
//!   through the book's `fad`);
//! - [`lease`]: the book's writer lease; [`wire`]: the daemon frame protocol;
//!   [`client`]: the `fa` side of that protocol;
//! - [`json`]: the closed-universe JSON reader and writer; [`args`]: the
//!   argument parser.

#![forbid(unsafe_code)]

mod access;
pub mod args;
pub mod authority;
mod bank;
mod case;
mod chart_role;
pub mod cli;
pub mod client;
mod closing;
mod consolidate;
mod custom_statement;
mod diff;
mod dimension;
mod disposal;
mod document;
mod engagement;
pub mod entry;
mod export;
mod external_subledger;
mod finding;
mod fx;
mod fx_revaluation;
mod intake;
mod intake_provenance;
mod issuance;
pub mod json;
mod laws;
pub mod lease;
mod migration_import;
pub(crate) mod notary;
mod obligation;
pub mod panic;
mod production;
mod proof;
mod query;
mod rea;
mod recurring;
mod refusal_object;
mod regulatory;
mod rule;
mod sample;
mod scenario;
mod subledger;
mod templates;
mod triage;
mod typed;
pub mod verbs;
pub mod wire;
