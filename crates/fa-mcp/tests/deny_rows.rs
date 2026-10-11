//! The deny.toml negative control (bead fa-xex, plan §18.4): the `chrono` and
//! `time` bans are confined to the exact `fastmcp-*` crates (and the crates
//! those pull) that import them, and never to a first-party crate — so a
//! direct first-party use of either would still be denied by `cargo deny
//! check bans` (a first-party crate is not a wrapper). This test pins the
//! wrapper lists byte for byte; `cargo deny check` itself is the positive
//! gate (`scripts/check.sh` step `deny`).
//!
//! deny.toml uses inline tables, which the registry TOML reader does not
//! parse; the rows are read line by line from the `deny = [` block.

use std::collections::BTreeSet;

const DENY: &str = include_str!("../../../deny.toml");

/// The `{ name = "<crate>", wrappers = [...] }` rows of `[bans] deny`, as
/// (name, wrappers).
fn ban_rows() -> Vec<(String, Vec<String>)> {
    let block = DENY
        .split("\ndeny = [")
        .nth(1)
        .and_then(|b| b.split("\n]").next())
        .expect("[bans] deny block");
    let mut rows = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("{ name = \"") else {
            continue;
        };
        let name = rest.split('"').next().expect("name").to_string();
        let wrappers = match rest.split("wrappers = [").nth(1) {
            None => Vec::new(),
            Some(w) => w
                .split(']')
                .next()
                .expect("wrappers")
                .split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        };
        rows.push((name, wrappers));
    }
    rows
}

fn wrappers_of(name: &str) -> Vec<String> {
    let rows = ban_rows();
    let matching: Vec<&(String, Vec<String>)> = rows.iter().filter(|(n, _)| n == name).collect();
    assert_eq!(matching.len(), 1, "exactly one ban row for `{name}`");
    matching[0].1.clone()
}

#[test]
fn chrono_and_time_are_banned_with_exactly_the_fastmcp_side_wrappers() {
    assert_eq!(wrappers_of("chrono"), vec!["fastmcp-server".to_string()]);
    assert_eq!(
        wrappers_of("time"),
        vec![
            "fastmcp-console".to_string(),
            "rich_rust".to_string(),
            "x509-parser".to_string(),
            "asn1-rs".to_string()
        ]
    );
    // The FrankenSymPy arithmetic wrappers gained only the fastmcp-side parents.
    assert_eq!(
        wrappers_of("num-bigint"),
        vec![
            "fsym-bigint".to_string(),
            "num-rational".to_string(),
            "der-parser".to_string()
        ]
    );
    assert_eq!(
        wrappers_of("num-rational"),
        vec!["fsym-rational".to_string(), "rich_rust".to_string()]
    );
    println!(
        "deny rows: chrono <- {:?}; time <- {:?}",
        wrappers_of("chrono"),
        wrappers_of("time")
    );
}

/// The negative control: no first-party crate is a wrapper of any banned
/// crate, so `fa-mcp` (or any `fa-*`) adding `chrono = "…"` to its manifest
/// would be an immediate parent that no row admits — `cargo deny check bans`
/// fails on it. The workspace members are read from the root manifest so a
/// new crate cannot slip in as a wrapper unnoticed.
#[test]
fn no_first_party_crate_is_a_wrapper_of_a_banned_crate() {
    let root = include_str!("../../../Cargo.toml");
    let members: BTreeSet<String> = root
        .split("members = [")
        .nth(1)
        .and_then(|m| m.split(']').next())
        .expect("workspace members")
        .lines()
        .filter_map(|l| {
            l.trim()
                .trim_matches(',')
                .trim_matches('"')
                .strip_prefix("crates/")
                .map(str::to_string)
        })
        .collect();
    assert!(
        members.contains("fa-mcp") && members.contains("fa-cli"),
        "{members:?}"
    );
    let rows = ban_rows();
    assert!(
        rows.iter().any(|(n, _)| n == "chrono") && rows.iter().any(|(n, _)| n == "time"),
        "chrono and time stay banned"
    );
    for (name, wrappers) in &rows {
        for w in wrappers {
            assert!(
                !members.contains(w),
                "`{w}` (first-party) is a wrapper of banned `{name}`"
            );
            assert!(
                !w.starts_with("fa-") && w != "fa" && w != "fad",
                "`{w}` looks first-party, wrapping `{name}`"
            );
        }
    }
    // A planted first-party wrapper is caught by this very check.
    let planted = (
        "chrono".to_string(),
        vec!["fastmcp-server".to_string(), "fa-mcp".to_string()],
    );
    assert!(
        planted.1.iter().any(|w| members.contains(w)),
        "the planted row would be refused"
    );
    println!(
        "deny rows: {} banned crates, no first-party wrapper among {} members",
        rows.len(),
        members.len()
    );
}
