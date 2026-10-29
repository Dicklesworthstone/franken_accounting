//! The excerpt policy for committed case data
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §1.3, §4.2, §14 OD 2a): whether a
//! sourced fact may carry its quote text, and how long that text may be.
//! A10a's ledger gate (`tests/ledgers.rs`) enforces both.

/// Owner decision 2a: committed case data may carry quote text. Until the
/// owner records that decision, facts are hash-first (anchor and
/// `quote_sha256` only) and every committed `quote` field fails the ledger
/// gate; the landing that flips this cites the recorded decision.
pub const QUOTE_TEXT_ALLOWED: bool = false;

/// The most words one fact's committed quote may carry once quote text is
/// allowed (§4.2).
pub const MAX_QUOTE_WORDS: usize = 60;
