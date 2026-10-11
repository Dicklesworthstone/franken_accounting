//! The README's "Try it today" section runs (bead fa-pq4): its files are
//! written verbatim, every `fa` line runs in order against the real binary
//! in a fresh directory, and each must exit 0. A README edit that breaks a
//! command breaks this test, so the section cannot drift from the binary.
//!
//! The harness is deliberately small: double-quoted words, a trailing
//! `> file`, and the `<document-oid>` placeholder filled from the `oid` the
//! previous line printed. Nothing else is interpreted.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

const README: &str = include_str!("../../../README.md");

struct Section {
    files: Vec<(String, String)>,
    commands: Vec<String>,
}

/// The fenced block that follows the line at `at`, as its lines.
fn fenced_after<'a>(lines: &[&'a str], at: usize) -> (Vec<&'a str>, usize) {
    let open = (at + 1..lines.len())
        .find(|&i| lines[i].starts_with("```"))
        .expect("a fenced block follows the marker");
    let close = (open + 1..lines.len())
        .find(|&i| lines[i].starts_with("```"))
        .expect("the fenced block closes");
    (lines[open + 1..close].to_vec(), close)
}

fn section(readme: &str) -> Section {
    let start = readme
        .find("\n### Try it today\n")
        .expect("README has a `### Try it today` section");
    let rest = &readme[start + 1..];
    let end = rest[4..].find("\n### ").map_or(rest.len(), |i| i + 4);
    let lines: Vec<&str> = rest[..end].lines().collect();
    let mut files = Vec::new();
    let mut commands = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if let Some(name) = line
            .strip_prefix("<!-- file: ")
            .and_then(|l| l.strip_suffix(" -->"))
        {
            let (body, close) = fenced_after(&lines, i);
            files.push((name.to_string(), format!("{}\n", body.join("\n"))));
            i = close;
        } else if line == "<!-- commands -->" {
            let (body, close) = fenced_after(&lines, i);
            commands.extend(
                body.iter()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_string),
            );
            i = close;
        }
        i += 1;
    }
    Section { files, commands }
}

/// Words of a command line: whitespace-separated, double quotes group.
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut word));
                    any = false;
                }
            }
            c => {
                word.push(c);
                any = true;
            }
        }
    }
    assert!(!quoted, "unbalanced quote in `{line}`");
    if any {
        out.push(word);
    }
    out
}

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fa-readme-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) => assert_eq!(
                error.kind(),
                std::io::ErrorKind::AlreadyExists,
                "create retained fixture {}: {error}",
                path.display()
            ),
        }
    }
}

/// Run `section` in a fresh directory; return each line's exit code and
/// stdout, stopping after the first failure.
fn execute(section: &Section) -> Vec<(String, i32, String)> {
    let dir = fixture();
    for (name, contents) in &section.files {
        std::fs::write(dir.join(name), contents).expect("write README file");
    }
    let mut oid: Option<String> = None;
    let mut ran = Vec::new();
    for line in &section.commands {
        let mut argv = words(line);
        let mut redirect = None;
        if argv.len() >= 2 && argv[argv.len() - 2] == ">" {
            redirect = argv.pop();
            argv.pop();
        }
        assert_eq!(argv.first().map(String::as_str), Some("fa"), "{line}");
        let argv: Vec<String> = argv[1..]
            .iter()
            .map(|w| {
                if w == "<document-oid>" {
                    oid.clone().expect("a previous line printed an oid")
                } else {
                    w.clone()
                }
            })
            .collect();
        let result = Command::new(env!("CARGO_BIN_EXE_fa"))
            .args(&argv)
            .current_dir(&dir)
            .env_remove("FA_BOOK")
            .output()
            .expect("run fa");
        let code = result.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
        eprintln!(
            "[readme] $ {line}\n  exit {code}\n  stdout: {}\n  stderr: {}",
            stdout.trim(),
            String::from_utf8_lossy(&result.stderr).trim()
        );
        if let Some(found) = json::parse(stdout.trim())
            .ok()
            .and_then(|l| l.get("data")?.get("oid")?.as_str().map(str::to_string))
        {
            oid = Some(found);
        }
        if let Some(file) = redirect {
            std::fs::write(dir.join(file), &stdout).expect("write redirected stdout");
        }
        ran.push((line.clone(), code, stdout));
        if code != 0 {
            break;
        }
    }
    ran
}

fn event(stdout: &str) -> Option<String> {
    json::parse(stdout.trim())
        .ok()
        .and_then(|l| l.get("event").and_then(Json::as_str).map(str::to_string))
}

#[test]
fn every_try_it_today_command_runs_against_the_real_binary() {
    let section = section(README);
    assert_eq!(
        section
            .files
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>(),
        ["invoice.txt", "sale.json"]
    );
    assert!(
        section.commands.len() >= 10,
        "the section is not vacuous: {:?}",
        section.commands
    );
    let ran = execute(&section);
    for (line, code, stdout) in &ran {
        assert_eq!(*code, 0, "README line failed: {line}\n{stdout}");
    }
    assert_eq!(ran.len(), section.commands.len(), "every line ran");
    let events: Vec<Option<String>> = ran.iter().map(|(_, _, out)| event(out)).collect();
    let replayed = ran
        .iter()
        .zip(&events)
        .find(|((line, _, _), _)| line.starts_with("fa replay"))
        .map(|(_, event)| event.clone());
    assert_eq!(
        replayed,
        Some(Some("certificate_replayed".to_string())),
        "the README's replay reproduces its trial balance"
    );
}

#[test]
fn a_try_it_today_line_with_a_flag_the_binary_lacks_fails_the_harness() {
    // The planted negative: the harness is not vacuous. One line gains a
    // flag the binary does not have, and that line, not a later one, fails
    // with exit 2.
    let mut section = section(README);
    let target = section
        .commands
        .iter()
        .position(|l| l.starts_with("fa chart import"))
        .expect("the section imports a chart");
    section.commands[target].push_str(" --no-such-flag");
    let ran = execute(&section);
    assert_eq!(ran.len(), target + 1, "execution stops at the edited line");
    let (line, code, _) = ran.last().expect("a line ran");
    assert!(line.ends_with("--no-such-flag"));
    assert_eq!(*code, 2);
    // And a section without commands is caught too.
    let empty = Section {
        files: Vec::new(),
        commands: Vec::new(),
    };
    assert!(execute(&empty).is_empty());
    assert_eq!(words("fa x \"a b\""), ["fa", "x", "a b"]);
    assert!(Path::new(env!("CARGO_BIN_EXE_fa")).exists());
}
