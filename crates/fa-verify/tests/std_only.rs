//! fa-verify's dependency allowlist is exactly `std` (plan §13.3): the
//! verifier must stay auditable in isolation and share no code with the
//! producer. Nothing else in the gate chain enforces that for this crate, so
//! its own manifest is the tripwire: any dependency table — normal, dev,
//! build, or target-specific — fails here.

const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn the_manifest_declares_no_dependency_table() {
    let tables: Vec<&str> = MANIFEST
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('[') && l.contains("dependencies"))
        .collect();
    assert!(
        tables.is_empty(),
        "fa-verify must depend on std alone; found {tables:?}"
    );
    // The tripwire sees the manifest it guards.
    assert!(MANIFEST.contains("name = \"fa-verify\""));
    assert!(MANIFEST.contains("[[bin]]"));
    assert!(MANIFEST.contains("path = \"src/main.rs\""));
}
