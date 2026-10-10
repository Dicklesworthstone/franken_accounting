//! The closed capability-op vocabulary (plan §14.2).
//!
//! Every op the admissibility matrix, a profile, an SoD rule, or a verb
//! cites resolves here; the parity test in `tests/policy.rs` enumerates the
//! registries against it. The position in [`Op::ALL`] is the durable tag in
//! `fa:capability:v1` and `fa:approval:v1`: additive only, never renumbered.

use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    Read,
    Post,
    PostSoftclosed,
    PostClosed,
    Approve,
    Reconcile,
    Close,
    Reopen,
    Restate,
    Migrate,
    SchemaChange,
    RuleChange,
    IssueCapability,
    Witness,
    Verify,
    Produce,
    Hold,
    Erase,
    Privileged,
    Receivership,
    PartialView,
}

impl Op {
    /// Every op, in durable tag order.
    pub const ALL: [Self; 21] = [
        Self::Read,
        Self::Post,
        Self::PostSoftclosed,
        Self::PostClosed,
        Self::Approve,
        Self::Reconcile,
        Self::Close,
        Self::Reopen,
        Self::Restate,
        Self::Migrate,
        Self::SchemaChange,
        Self::RuleChange,
        Self::IssueCapability,
        Self::Witness,
        Self::Verify,
        Self::Produce,
        Self::Hold,
        Self::Erase,
        Self::Privileged,
        Self::Receivership,
        Self::PartialView,
    ];

    /// The registered name, exactly as `admissibility.toml`, `sod_policy.toml`
    /// and `--grant` spell it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Post => "post",
            Self::PostSoftclosed => "post_softclosed",
            Self::PostClosed => "post_closed",
            Self::Approve => "approve",
            Self::Reconcile => "reconcile",
            Self::Close => "close",
            Self::Reopen => "reopen",
            Self::Restate => "restate",
            Self::Migrate => "migrate",
            Self::SchemaChange => "schema_change",
            Self::RuleChange => "rule_change",
            Self::IssueCapability => "issue_capability",
            Self::Witness => "witness",
            Self::Verify => "verify",
            Self::Produce => "produce",
            Self::Hold => "hold",
            Self::Erase => "erase",
            Self::Privileged => "privileged",
            Self::Receivership => "receivership",
            Self::PartialView => "partial_view",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.name() == name)
    }

    /// The durable tag: the op's position in [`Op::ALL`].
    #[must_use]
    pub fn tag(self) -> u8 {
        match Self::ALL.iter().position(|op| *op == self) {
            // ALL holds 21 entries, so the position always fits a u8.
            Some(i) => u8::try_from(i).unwrap_or(u8::MAX),
            None => u8::MAX,
        }
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.get(usize::from(tag)).copied()
    }

    /// The registered op nearest to a misspelling (edit distance ≤ 2), for
    /// a usage error's fix.
    #[must_use]
    pub fn nearest(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .map(|op| (edit_distance(name, op.name()), op))
            .filter(|(d, _)| *d <= 2)
            .min_by_key(|(d, op)| (*d, op.tag()))
            .map(|(_, op)| op)
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Levenshtein distance over chars; the inputs are short op names.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = Vec::with_capacity(b.len() + 1);
        cur.push(i + 1);
        for (j, cb) in b.iter().enumerate() {
            let substitute = prev[j] + usize::from(ca != *cb);
            cur.push(substitute.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_tags_round_trip_and_are_unique() {
        let mut names = std::collections::BTreeSet::new();
        for (i, op) in Op::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(op.tag()), i);
            assert_eq!(Op::from_tag(op.tag()), Some(op));
            assert_eq!(Op::from_name(op.name()), Some(op));
            assert!(names.insert(op.name()));
        }
        assert_eq!(Op::from_tag(21), None);
        assert_eq!(Op::from_name("POST"), None);
    }

    #[test]
    fn nearest_suggests_a_registered_op_for_a_typo() {
        assert_eq!(Op::nearest("post_clsoed"), Some(Op::PostClosed));
        assert_eq!(Op::nearest("aprove"), Some(Op::Approve));
        assert_eq!(Op::nearest("teleport"), None);
    }
}
