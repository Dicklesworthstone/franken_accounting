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

/// Every committed case.
pub const CASES: &[EmbeddedCase] = &[SELFTEST, WORLDCOM, XBRL, LEHMAN, ENRON];

/// The harness self-test (A7a; A8a completes it).
pub const SELFTEST: EmbeddedCase = EmbeddedCase {
    id: "_selftest",
    files: &[
        ("case.toml", include_str!("../../cases/_selftest/case.toml")),
        (
            "roles.toml",
            include_str!("../../cases/_selftest/roles.toml"),
        ),
        (
            "facts.toml",
            include_str!("../../cases/_selftest/facts.toml"),
        ),
        (
            "books/native.toml",
            include_str!("../../cases/_selftest/books/native.toml"),
        ),
        (
            "expectations.toml",
            include_str!("../../cases/_selftest/expectations.toml"),
        ),
    ],
};

/// WorldCom (W1: the sources ledger and receipts; A8: the pilot on the
/// native book; W2-W9 add the rest).
pub const WORLDCOM: EmbeddedCase = EmbeddedCase {
    id: "worldcom",
    files: &[
        ("case.toml", include_str!("../../cases/worldcom/case.toml")),
        (
            "sources.toml",
            include_str!("../../cases/worldcom/sources.toml"),
        ),
        (
            "facts.toml",
            include_str!("../../cases/worldcom/facts.toml"),
        ),
        (
            "receipts.toml",
            include_str!("../../cases/worldcom/receipts.toml"),
        ),
        (
            "roles.toml",
            include_str!("../../cases/worldcom/roles.toml"),
        ),
        (
            "books/native.toml",
            include_str!("../../cases/worldcom/books/native.toml"),
        ),
        (
            "books/statement.toml",
            include_str!("../../cases/worldcom/books/statement.toml"),
        ),
        (
            "books/migration.toml",
            include_str!("../../cases/worldcom/books/migration.toml"),
        ),
        (
            "expectations.toml",
            include_str!("../../cases/worldcom/expectations.toml"),
        ),
        ("README.md", include_str!("../../cases/worldcom/README.md")),
    ],
};

/// The XBRL-era restatements (X3's slices 1 and 2: SunPower's 10-K/A
/// income-statement and balance-sheet books; X1-X7 add the rest).
pub const XBRL: EmbeddedCase = EmbeddedCase {
    id: "xbrl",
    files: &[
        ("case.toml", include_str!("../../cases/xbrl/case.toml")),
        (
            "sources.toml",
            include_str!("../../cases/xbrl/sources.toml"),
        ),
        ("facts.toml", include_str!("../../cases/xbrl/facts.toml")),
        (
            "receipts.toml",
            include_str!("../../cases/xbrl/receipts.toml"),
        ),
        ("roles.toml", include_str!("../../cases/xbrl/roles.toml")),
        (
            "books/statement-sunpower-is.toml",
            include_str!("../../cases/xbrl/books/statement-sunpower-is.toml"),
        ),
        (
            "books/statement-sunpower.toml",
            include_str!("../../cases/xbrl/books/statement-sunpower.toml"),
        ),
        (
            "books/statement-sunpower-fy2021.toml",
            include_str!("../../cases/xbrl/books/statement-sunpower-fy2021.toml"),
        ),
        (
            "expectations.toml",
            include_str!("../../cases/xbrl/expectations.toml"),
        ),
        ("README.md", include_str!("../../cases/xbrl/README.md")),
    ],
};

/// Lehman Repo 105 (L2's slice 1: the Q2-2008 10-Q's statement footings;
/// L1-L4 add the Valukas sources, the scenario and the rest).
pub const LEHMAN: EmbeddedCase = EmbeddedCase {
    id: "lehman",
    files: &[
        ("case.toml", include_str!("../../cases/lehman/case.toml")),
        (
            "sources.toml",
            include_str!("../../cases/lehman/sources.toml"),
        ),
        ("facts.toml", include_str!("../../cases/lehman/facts.toml")),
        (
            "receipts.toml",
            include_str!("../../cases/lehman/receipts.toml"),
        ),
        ("roles.toml", include_str!("../../cases/lehman/roles.toml")),
        (
            "books/statement.toml",
            include_str!("../../cases/lehman/books/statement.toml"),
        ),
        (
            "books/statement-fy2007.toml",
            include_str!("../../cases/lehman/books/statement-fy2007.toml"),
        ),
        (
            "expectations.toml",
            include_str!("../../cases/lehman/expectations.toml"),
        ),
        ("README.md", include_str!("../../cases/lehman/README.md")),
    ],
};

/// Enron (E1: the sources ledger and its assurance facts; E2a-E4 add the
/// facts, books and claims).
pub const ENRON: EmbeddedCase = EmbeddedCase {
    id: "enron",
    files: &[
        ("case.toml", include_str!("../../cases/enron/case.toml")),
        (
            "sources.toml",
            include_str!("../../cases/enron/sources.toml"),
        ),
        ("facts.toml", include_str!("../../cases/enron/facts.toml")),
        (
            "receipts.toml",
            include_str!("../../cases/enron/receipts.toml"),
        ),
        ("roles.toml", include_str!("../../cases/enron/roles.toml")),
        ("README.md", include_str!("../../cases/enron/README.md")),
    ],
};

impl EmbeddedCase {
    /// The case's files as a [`super::CaseFiles`].
    #[must_use]
    pub const fn case_files(&self) -> super::CaseFiles<'static> {
        super::CaseFiles {
            id: self.id,
            files: self.files,
        }
    }
}

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
    fn every_committed_case_loads_and_no_load_check_fails() {
        for case in CASES {
            let loaded = crate::cases::load(&case.case_files());
            assert!(loaded.is_ok(), "{}: {:#?}", case.id, loaded.err());
            let Ok(loaded) = loaded else { continue };
            for report in crate::cases::check::run_load_checks(&loaded) {
                assert_ne!(
                    report.verdict,
                    crate::cases::check::Verdict::Fail,
                    "{}:\n{}",
                    case.id,
                    report.render(Some(case.id))
                );
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
