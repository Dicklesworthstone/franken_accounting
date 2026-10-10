//! FrankenAccounting — the embedded library (`fa`).
//!
//! The single source of truth for what this crate becomes is
//! `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md` (§15.2 for the
//! embedded API). This increment is the Genesis witness only: [`book::Book`]
//! opens a book on FrankenGraphDB under the production asupersync runtime and
//! round-trips a write. Everything else in §15.2 — sessions, intents, plans,
//! certified reads, drafts, bundles — lands as later slices of this same
//! crate, never as a substitute.
//!
//! Doctrine that already binds this crate (AGENTS.md): no `unsafe`; every
//! effectful call takes a substrate purpose context derived from an
//! asupersync `Cx`; recorded time is the substrate's `CommitSeq`; nothing
//! here reads a wall clock.

#![forbid(unsafe_code)]

pub mod book;
