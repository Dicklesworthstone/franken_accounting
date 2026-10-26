//! fa-oracles: the public-record forensic case studies' harness model
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.1).
//!
//! The case model (sources, provenance-typed facts, receipts, book variants,
//! expectations, derivations, branch enumeration) lives here, and the
//! runner that replays a case through the real `fa` binary lives in
//! `crates/fa-cli/tests/cases.rs`. This crate is the verification layer's
//! external-oracle home (COMPREHENSIVE_PLAN §16.3): published tie-outs are
//! external oracles of the engine.
//!
//! Engine independence (plan §3.1): fa-oracles does its own exact integer
//! arithmetic and has its own SHA-256 ([`sha256`]), so a bug shared with the
//! engine cannot make a tie-out agree. Its topology allowlist admits only
//! fa-registry (the registries and their TOML subset), fa-reference (the
//! independent oracle) and fa-time (the dates fa-reference's API takes).
//!
//! Item A1a (bead fa-yugf.3) lands the crate, its SHA-256 and the loaders of
//! a case's `case.toml`, `sources.toml`, `facts.toml`, `receipts.toml` and
//! `roles.toml` ([`cases`]).

#![forbid(unsafe_code)]

pub mod cases;
pub mod sha256;
