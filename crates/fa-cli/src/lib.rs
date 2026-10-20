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

pub mod args;
pub mod authority;
mod bank;
pub mod cli;
pub mod client;
mod closing;
mod document;
pub mod entry;
mod export;
mod finding;
mod fx;
mod fx_revaluation;
mod intake;
mod intake_provenance;
mod issuance;
pub mod json;
pub mod lease;
mod migration_import;
pub(crate) mod notary;
pub mod panic;
mod production;
mod proof;
mod rea;
mod sample;
mod scenario;
mod templates;
mod triage;
mod typed;
pub mod verbs;
pub mod wire;
