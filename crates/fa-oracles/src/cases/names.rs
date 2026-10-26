//! Name tokens and their deny-list hashes (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §2.8; bead fa-yugf.9, A3c).
//!
//! Real people appear only as role labels. `roles.toml`'s `[deny] hashes`
//! lists the SHA-256 of each name token a case must never carry, under the
//! normalization `fa:case-name-token:v1`: A3a's whitespace normalization,
//! then a split on every character that is not a Unicode letter or digit,
//! then `char::to_lowercase` per token. A token's hash is the hex SHA-256 of
//! `fa:case-name-token:v1`, one 0x00 byte and the token's UTF-8 bytes, which
//! an author computes without writing the name to any file:
//! `printf 'fa:case-name-token:v1\0%s' "$token" | sha256sum`.

use super::normalize::normalize_str;
use crate::sha256;

/// The normalization's domain tag.
pub const TAG: &str = "fa:case-name-token:v1";

/// The normalized name tokens of `text`, in order.
#[must_use]
pub fn name_tokens(text: &str) -> Vec<String> {
    normalize_str(text)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.chars().flat_map(char::to_lowercase).collect())
        .collect()
}

/// The deny-list hash of one normalized token.
#[must_use]
pub fn deny_hash(token: &str) -> String {
    let mut bytes = Vec::with_capacity(TAG.len() + 1 + token.len());
    bytes.extend_from_slice(TAG.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(token.as_bytes());
    sha256::hex(&sha256::digest(&bytes))
}

/// The deny-listed hashes among `text`'s tokens, each once, in order.
#[must_use]
pub fn denied(text: &str, deny: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in name_tokens(text) {
        let h = deny_hash(&t);
        if deny.contains(&h) && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `printf 'fa:case-name-token:v1\0%s' testname | sha256sum`.
    const TESTNAME_HASH: &str = "51d3ec987f0103dda5d27b9fa799a70ad7ea10ecaa27c9e52ed97f8f380124de";

    #[test]
    fn deny_hash_matches_the_documented_shell_command() {
        assert_eq!(deny_hash("testname"), TESTNAME_HASH);
    }

    #[test]
    fn name_tokens_split_on_non_alphanumerics_and_lower_case() {
        assert_eq!(
            name_tokens("TestName-1\u{a0} the  Ä-Ö report"),
            ["testname", "1", "the", "ä", "ö", "report"]
        );
        assert_eq!(
            denied("principal testname-1 and TESTNAME", &[TESTNAME_HASH.into()]),
            [TESTNAME_HASH]
        );
        assert!(denied("testnames", &[TESTNAME_HASH.into()]).is_empty());
    }
}
