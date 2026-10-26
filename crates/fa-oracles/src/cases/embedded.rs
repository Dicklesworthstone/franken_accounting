//! The committed cases, embedded with `include_str!` so the crate's verdict
//! hash covers every case file (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.1).
//!
//! `include_str!` needs literal paths, so every item that commits a file
//! under `crates/fa-oracles/cases/<dir>/` adds its line here, generated
//! files included (`receipts.toml`, rows files, the rendered READMEs). The
//! test `embedded_index_lists_every_committed_file` fails, naming the file,
//! when a committed case file has no line here.

/// One committed case: its directory name and its files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddedCase {
    pub id: &'static str,
    pub files: &'static [(&'static str, &'static str)],
}

/// Every committed case (none yet; the self-test, A7a, is the first).
pub const CASES: &[EmbeddedCase] = &[];

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::CASES;

    fn files_under(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files_under(&path, base, out);
            } else if let Ok(rel) = path.strip_prefix(base) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }

    #[test]
    fn embedded_index_lists_every_committed_file() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cases");
        let mut on_disk = Vec::new();
        files_under(&root, &root, &mut on_disk);
        on_disk.sort();
        let indexed: Vec<String> = CASES
            .iter()
            .flat_map(|c| c.files.iter().map(move |(p, _)| format!("{}/{p}", c.id)))
            .collect();
        let missing: Vec<&String> = on_disk.iter().filter(|f| !indexed.contains(f)).collect();
        assert!(
            missing.is_empty(),
            "committed case files with no line in src/cases/embedded.rs (invisible to every check): {missing:?}"
        );
    }
}
