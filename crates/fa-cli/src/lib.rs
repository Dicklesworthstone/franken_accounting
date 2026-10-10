//! The reusable parts of the `fa` command line: the closed-universe JSON
//! reader and writer, and the verb registry (`registries/verbs.toml`) that
//! drives the binary's dispatch, flags, help, and robot-mode schema. The
//! binary is `src/main.rs`; its tests read robot output through this library.

#![forbid(unsafe_code)]

pub mod json;
pub mod verbs;
