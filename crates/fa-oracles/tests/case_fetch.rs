//! The gate for `tools/case-fetch` (docs/FORENSIC_CASE_STUDIES_PLAN.md §15
//! A9; bead fa-yugf.22).
//!
//! The tool is Python outside the workspace: it needs an HTTP client and runs
//! only at authoring time (§4.4). This test is how `cargo test` runs its
//! stdlib unittest suite, and it pins the exact tool bytes a green run tested
//! (`crates/fa-oracles/data/case_fetch.sha256`). The two `include_str!`s make
//! fa-oracles read outside its own tree, which `scripts/crate_verdicts.py`
//! marks `undeclared_external_read`: fa-oracles' verdict is never reused while
//! the tool lives outside the crate, so an edit to the tool alone always
//! re-runs this gate.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const TOOL: &str = include_str!("../../../tools/case-fetch/case_fetch.py");
const SUITE: &str = include_str!("../../../tools/case-fetch/test_case_fetch.py");
const PIN: &str = include_str!("../data/case_fetch.sha256");
const TOOL_DIR: &str = "tools/case-fetch";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs `python3 -B -m unittest discover` over `dir` from the repository
/// root; `Err` carries the transcript (or why python3 could not run).
fn run_unittests(dir: &Path) -> Result<String, String> {
    let out = Command::new("python3")
        .arg("-B")
        .args(["-m", "unittest", "discover", "-v", "-s"])
        .arg(dir)
        .arg("-t")
        .arg(dir)
        .current_dir(root())
        .env("NO_COLOR", "1")
        .env("PYTHON_COLORS", "0")
        .env_remove("FORCE_COLOR")
        .output()
        .map_err(|e| {
            format!("FAIL case_fetch gate: python3 not found on PATH (this is not a pass): {e}")
        })?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!(
            "FAIL case_fetch gate: unittest exited {:?}\n{text}",
            out.status.code()
        ))
    }
}

/// Every file under `dir`, as (path relative to the repository root, bytes),
/// sorted; bytecode caches are not tool sources.
fn tool_files(dir: &Path, rel: &str, out: &mut Vec<(String, Vec<u8>)>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("the tool directory is readable")
        .map(|e| e.expect("a directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a UTF-8 file name")
            .to_string();
        let rel = format!("{rel}/{name}");
        if path.is_dir() {
            if name != "__pycache__" {
                tool_files(&path, &rel, out);
            }
        } else if !name.ends_with(".pyc") {
            out.push((rel, fs::read(&path).expect("a tool file")));
        }
    }
}

/// The pin's disagreements with `files`: each names the file.
fn pin_problems(pin: &str, files: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut pinned = std::collections::BTreeMap::new();
    let mut problems = Vec::new();
    for line in pin.lines().filter(|l| !l.is_empty()) {
        match line.split_once("  ") {
            Some((digest, path)) => {
                pinned.insert(path.to_string(), digest.to_string());
            }
            None => problems.push(format!("malformed pin line `{line}`")),
        }
    }
    for (path, bytes) in files {
        let digest = fa_oracles::sha256::hex(&fa_oracles::sha256::digest(bytes));
        match pinned.remove(path) {
            None => problems.push(format!("{path} is not in case_fetch.sha256")),
            Some(want) if want != digest => problems.push(format!(
                "{path} has sha256 {digest}, case_fetch.sha256 pins {want}"
            )),
            Some(_) => {}
        }
    }
    problems.extend(
        pinned
            .into_keys()
            .map(|path| format!("{path} is pinned but absent")),
    );
    problems
}

fn current_files() -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    tool_files(&root().join(TOOL_DIR), TOOL_DIR, &mut files);
    files
}

#[test]
fn case_fetch_unittests_pass() {
    let dir = root().join(TOOL_DIR);
    assert_eq!(
        fs::read_to_string(dir.join("case_fetch.py")).expect("case_fetch.py"),
        TOOL,
        "the embedded tool is the file on disk"
    );
    assert_eq!(
        fs::read_to_string(dir.join("test_case_fetch.py")).expect("test_case_fetch.py"),
        SUITE,
        "the embedded suite is the file on disk"
    );
    if let Ok(v) = Command::new("python3").arg("--version").output() {
        println!(
            "case_fetch gate: {}",
            String::from_utf8_lossy(&v.stdout).trim()
        );
    }
    match run_unittests(&dir) {
        Ok(transcript) => {
            println!("{transcript}");
            let ran = transcript
                .lines()
                .find_map(|l| {
                    l.strip_prefix("Ran ")?
                        .split_once(" test")?
                        .0
                        .parse::<u32>()
                        .ok()
                })
                .unwrap_or(0);
            assert!(
                ran > 0 && transcript.lines().any(|l| l == "OK"),
                "a passing unittest transcript ran at least one test:\n{transcript}"
            );
        }
        Err(transcript) => panic!("{transcript}"),
    }
}

#[test]
fn case_fetch_runner_reports_a_planted_failing_unittest() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("case_fetch_planted");
    fs::create_dir_all(&dir).expect("planted dir");
    fs::write(
        dir.join("test_planted.py"),
        "import unittest\n\n\nclass Planted(unittest.TestCase):\n    def test_passes(self):\n        self.assertTrue(True)\n\n    def test_planted_failure(self):\n        self.assertEqual(1, 2)\n",
    )
    .expect("planted test");
    let transcript = run_unittests(&dir).expect_err("a failing unittest fails the gate");
    assert!(
        transcript.contains("test_planted_failure") && transcript.contains("FAILED"),
        "{transcript}"
    );
}

#[test]
fn case_fetch_sources_match_their_pin() {
    let files = current_files();
    assert!(
        files.iter().any(|(p, _)| p.ends_with("/case_fetch.py"))
            && files
                .iter()
                .any(|(p, _)| p.ends_with("/test_case_fetch.py")),
        "the tool and its suite are pinned"
    );
    let problems = pin_problems(PIN, &files);
    assert!(
        problems.is_empty(),
        "case_fetch.sha256 is stale:\n{}",
        problems.join("\n")
    );
}

#[test]
fn a_tool_file_changed_without_its_pin_line_is_named() {
    let mut files = current_files();
    let (path, bytes) = files
        .iter_mut()
        .find(|(p, _)| p.ends_with("/case_fetch.py"))
        .expect("case_fetch.py");
    bytes.extend_from_slice(b"\n# planted edit\n");
    let path = path.clone();
    let problems = pin_problems(PIN, &files);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].starts_with(&path), "{problems:?}");

    let mut extra = current_files();
    extra.push((format!("{TOOL_DIR}/unpinned.py"), b"x".to_vec()));
    assert_eq!(
        pin_problems(PIN, &extra),
        vec![format!(
            "{TOOL_DIR}/unpinned.py is not in case_fetch.sha256"
        )]
    );
}
