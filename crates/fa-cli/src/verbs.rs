//! The verb registry (`registries/verbs.toml`), re-exported from [`fa_verbs`].

pub use fa_verbs::{
    Alias, BOOK_FIELDS, Condition, Daemon, Dangerous, ENVELOPE_FIELDS, ENVELOPE_VERSION, Envelope,
    Field, Global, NextAction, PAYLOAD, Registry, SOURCE, Scalar, Schema, TYPES, Type, Verb,
    registry,
};
