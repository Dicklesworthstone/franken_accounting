//! The substrate behavior suite (plan §16.3, bead fa-zy1).
//!
//! The kernel's correctness rests on a handful of FrankenGraphDB behaviors:
//! an existing identity is refused, and refused while staging; a transaction
//! whose snapshot fell behind is refused at staging, and `refresh_snapshot`
//! revalidates exactly its witnesses; a witnessed row changed by another
//! committer loses first-committer-wins in either order; `delta_since` is
//! gap-free in commit order; a certified read replays byte-identically at its
//! snapshot. `tests/substrate.rs` holds one test per behavior against the
//! pinned `fgdb` API directly, never through the kernel, each asserting the
//! exact typed outcome beside a control that must not trip it.
//!
//! Mutation run: `FA_CONFORMANCE_INVERT=<test name>` inverts that one test's
//! expectation, so `scripts/conformance_mutation.sh` proves every test fails
//! when its behavior is absent and only that test fails.
//!
//! No-claim boundary: the behaviors are proved at the pinned revision only;
//! a pin bump re-runs the suite. Retired delta cursors, crash points and
//! directory-book parity are later rows.

#![forbid(unsafe_code)]
