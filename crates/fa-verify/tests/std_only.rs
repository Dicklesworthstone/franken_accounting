//! fa-verify's dependency allowlist is exactly `std` (plan §13.3): the
//! verifier must stay auditable in isolation and share no code with the
//! producer. Nothing else in the gate chain enforces that for this crate, so
//! its own manifest is the tripwire: any dependency table — normal, dev,
//! build, or target-specific — fails here.

const MANIFEST: &str = include_str!("../Cargo.toml");
const LIB_SRC: &str = include_str!("../src/lib.rs");
const MAIN_SRC: &str = include_str!("../src/main.rs");

fn validate_std_only_manifest(manifest: &str) -> Result<(), String> {
    let tables: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter(|l| {
            (l.starts_with('[') && l.contains("dependencies"))
                || l.starts_with("dependencies.")
                || l.starts_with("dev-dependencies.")
                || l.starts_with("build-dependencies.")
        })
        .collect();
    if !tables.is_empty() {
        return Err(format!(
            "fa-verify must depend on std alone; found {tables:?}"
        ));
    }
    if !manifest.contains("name = \"fa-verify\"") {
        return Err("manifest must declare package name = \"fa-verify\"".into());
    }
    if !manifest.contains("[[bin]]") || !manifest.contains("path = \"src/main.rs\"") {
        return Err("manifest must declare [[bin]] target at src/main.rs".into());
    }
    Ok(())
}

#[test]
fn the_manifest_declares_no_dependency_table() {
    validate_std_only_manifest(MANIFEST).expect("fa-verify Cargo.toml is std-only with bin target");
    assert!(LIB_SRC.contains("#![forbid(unsafe_code)]"));
    assert!(MAIN_SRC.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn planted_dependency_in_manifest_fails_std_only_guard() {
    for planted in [
        format!("{MANIFEST}\n[dependencies]\nserde = \"1.0\"\n"),
        format!("{MANIFEST}\n[dev-dependencies]\nproptest = \"1.0\"\n"),
        format!("{MANIFEST}\n[build-dependencies]\ncc = \"1.0\"\n"),
        format!("{MANIFEST}\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n"),
        format!("{MANIFEST}\ndependencies.serde = \"1.0\"\n"),
        MANIFEST.replace("[[bin]]", "# no bin"),
    ] {
        let err = validate_std_only_manifest(&planted)
            .expect_err("planted dependency or missing bin target must fail std-only guard");
        assert!(!err.is_empty());
    }
}
