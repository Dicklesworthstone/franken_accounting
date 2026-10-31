//! A narrow executable target for the public native procedure workflow.
//! Shared fixtures also run with the crate's unit suite.

#![forbid(unsafe_code)]

pub use fa::{Book, BookKeys, Entropy, query};

#[path = "../src/query/pipeline/tests.rs"]
mod tests;
