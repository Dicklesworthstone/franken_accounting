//! The README's "Try it today" section runs (bead fa-pq4): its files are
//! written verbatim, every `fa` line runs in order against the real binary
//! in a fresh directory, and each must exit 0; the replay must reproduce the
//! certified trial balance's robot line byte for byte (FA-INV-11). A README
//! edit that breaks a command breaks this test, so the section cannot drift
//! from the binary.
//!
//! Every other `fa` line the README presents as working today, in a fenced
//! shell block above `## TL;DR` (where the README switches to the 1.0 target
//! state), is checked against the verb registry: a registered verb or alias,
//! one of its subcommands where it has them, and only flags the verb or the
//! global table accepts. The parity gate ties the registry to the binary, so
//! a stale flag or an invented verb there fails here too.
//!
//! The harness is deliberately small: double-quoted words, and the
//! `<document-oid>` placeholder filled from the `oid` of the last `document`
//! event. Nothing else is interpreted.
//!
//! No-claim boundary: the registry check proves names, not behavior; lines
//! below `## TL;DR` describe the target state and are not checked.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_cli::verbs::{Registry, registry};

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

/// The robot lines of one command's stdout.
fn robot_lines(stdout: &str) -> Vec<Json> {
    stdout
        .lines()
        .map(|line| json::parse(line).unwrap_or_else(|e| panic!("not a robot line: {line}: {e:?}")))
        .collect()
}

fn event(line: &Json) -> Option<&str> {
    line.get("event").and_then(Json::as_str)
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
        let argv = words(line);
        assert_eq!(argv.first().map(String::as_str), Some("fa"), "{line}");
        let argv: Vec<String> = argv[1..]
            .iter()
            .map(|w| {
                if w == "<document-oid>" {
                    oid.clone().expect("a `document` event printed an oid")
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
        for robot in stdout.lines().filter_map(|l| json::parse(l).ok()) {
            if event(&robot) == Some("document")
                && let Some(found) = robot.get("data").and_then(|d| d.get("oid"))
            {
                oid = found.as_str().map(str::to_string);
            }
        }
        ran.push((line.clone(), code, stdout));
        if code != 0 {
            break;
        }
    }
    ran
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
    let output = |prefix: &str| -> &str {
        ran.iter()
            .find(|(line, _, _)| line.starts_with(prefix))
            .map(|(_, _, stdout)| stdout.as_str())
            .unwrap_or_else(|| panic!("the section runs `{prefix}`"))
    };
    // The certified report is the trial balance line and then its
    // certificate; the replay reproduces that first line byte for byte.
    let certified = output("fa tb ");
    let robots = robot_lines(certified);
    assert_eq!(
        robots.iter().map(event).collect::<Vec<_>>(),
        [Some("trial_balance"), Some("report_certificate")],
        "{certified}"
    );
    let replayed = output("fa replay ");
    assert_eq!(
        replayed.lines().collect::<Vec<_>>(),
        certified.lines().take(1).collect::<Vec<_>>(),
        "the README's replay reproduces its certified trial balance"
    );
    let status = robot_lines(output("fa certificate status "));
    assert_eq!(
        status
            .first()
            .and_then(|l| l.get("data"))
            .and_then(|d| d.get("status"))
            .and_then(Json::as_str),
        Some("Current"),
        "{status:?}"
    );
}

#[test]
fn a_try_it_today_line_with_a_flag_or_verb_the_binary_lacks_fails_the_harness() {
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
    // A README line that claims a verb the binary does not have (the
    // target-state `fa invoice`) also stops the harness there, exit 2.
    let mut section = self::section(README);
    let target = section
        .commands
        .iter()
        .position(|l| l.starts_with("fa post"))
        .expect("the section posts an entry");
    section.commands[target] = "fa invoice --party ACME-CUST-17 --book acme --json".to_string();
    let ran = execute(&section);
    assert_eq!(
        ran.len(),
        target + 1,
        "execution stops at the invented verb"
    );
    assert_eq!(ran.last().map(|(_, code, _)| *code), Some(2));
    // And a section without commands is caught too.
    let empty = Section {
        files: Vec::new(),
        commands: Vec::new(),
    };
    assert!(execute(&empty).is_empty());
    assert_eq!(words("fa x \"a b\""), ["fa", "x", "a b"]);
    assert!(Path::new(env!("CARGO_BIN_EXE_fa")).exists());
}

/// Every `fa` line in a fenced shell block above `## TL;DR`, with
/// backslash continuations joined.
fn present_tense_lines(readme: &str) -> Vec<String> {
    let (now, _) = readme
        .split_once("\n## TL;DR\n")
        .expect("README has a `## TL;DR` heading");
    let mut out = Vec::new();
    let mut shell = None;
    let mut pending = String::new();
    for raw in now.lines() {
        if let Some(lang) = raw.strip_prefix("```") {
            shell = match shell {
                None => Some(matches!(
                    lang.trim(),
                    "" | "bash" | "sh" | "shell" | "console"
                )),
                Some(_) => None,
            };
            pending.clear();
            continue;
        }
        if shell != Some(true) {
            continue;
        }
        let part = raw.trim();
        let joined = if pending.is_empty() {
            part.to_string()
        } else {
            format!("{pending} {part}")
        };
        if let Some(head) = joined.strip_suffix('\\') {
            pending = head.trim_end().to_string();
            continue;
        }
        pending.clear();
        if joined.starts_with("fa ") {
            out.push(joined);
        }
    }
    out
}

/// What the registry says is wrong with the command `line`, if anything.
fn unregistered(reg: &Registry, line: &str) -> Option<String> {
    let mut rest: Vec<String> = words(line).into_iter().skip(1).collect();
    let first = rest.first()?.clone();
    if reg.verb(&first).is_none()
        && let Some(alias) = reg.alias(&first)
    {
        rest.splice(0..1, alias.expands.iter().cloned());
    }
    let Some(verb) = reg.verb(&rest[0]) else {
        return Some(format!("`{line}`: `{}` is not a registered verb", rest[0]));
    };
    if !verb.subcommands.is_empty()
        && !rest
            .get(1)
            .is_some_and(|sub| verb.subcommands.contains(sub))
    {
        return Some(format!(
            "`{line}`: `{}` takes one of the subcommands {:?}",
            verb.name, verb.subcommands
        ));
    }
    for word in &rest[1..] {
        if !word.starts_with("--") {
            continue;
        }
        let flag = word.split_once('=').map_or(word.as_str(), |(flag, _)| flag);
        let global = reg
            .global
            .flags
            .iter()
            .chain(&reg.global.switches)
            .any(|g| g == flag);
        if !global && !verb.accepts(flag) {
            return Some(format!(
                "`{line}`: `{}` does not accept `{flag}`",
                verb.name
            ));
        }
    }
    None
}

#[test]
fn every_fa_line_the_readme_presents_as_working_today_is_registered() {
    let reg = registry().expect("verbs.toml");
    let lines = present_tense_lines(README);
    assert!(
        lines.len() >= 20,
        "the README's present-tense examples are not vacuous: {lines:#?}"
    );
    let wrong: Vec<String> = lines.iter().filter_map(|l| unregistered(reg, l)).collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn the_registry_check_names_an_invented_verb_subcommand_or_flag() {
    // The planted negatives: an invented verb, a subcommand the verb lacks,
    // and a flag it does not accept (behind a continuation) are each named;
    // a registered line, a comment, a non-shell block and the target-state
    // half below `## TL;DR` are not.
    let reg = registry().expect("verbs.toml");
    let planted = "Intro\n\n```bash\n# fa comment --ignored\n\
        fa tb --period FY2026-P03 --json\nfa invoice --party ACME\n\
        fa verify nonsense --json\nfa tb --period FY2026-P03 \\\n  --no-such-flag --json\n```\n\n\
        ```rust\nfa not shell\n```\n\n## TL;DR\n\n```bash\nfa invoice --target-state\n```\n";
    let lines = present_tense_lines(planted);
    assert_eq!(
        lines,
        [
            "fa tb --period FY2026-P03 --json",
            "fa invoice --party ACME",
            "fa verify nonsense --json",
            "fa tb --period FY2026-P03 --no-such-flag --json",
        ]
    );
    let verdicts: Vec<Option<String>> = lines.iter().map(|l| unregistered(reg, l)).collect();
    assert_eq!(verdicts[0], None);
    for (verdict, names) in
        verdicts[1..]
            .iter()
            .zip(["`invoice`", "subcommands", "`--no-such-flag`"])
    {
        assert!(
            verdict.as_deref().is_some_and(|v| v.contains(names)),
            "{verdict:?} should name {names}"
        );
    }
}

#[test]
fn target_state_commands_below_tldr_are_registered_or_name_a_target_bead() {
    let reg = registry().expect("verbs.toml");
    let (_, after_tldr) = README
        .split_once("\n## TL;DR\n")
        .expect("README has a `## TL;DR` heading");
    let mut shell = None;
    let mut pending = String::new();
    let mut last_comment = String::new();
    let mut checked = 0usize;
    for raw in after_tldr.lines() {
        if let Some(lang) = raw.strip_prefix("```") {
            shell = match shell {
                None => Some(matches!(
                    lang.trim(),
                    "" | "bash" | "sh" | "shell" | "console"
                )),
                Some(_) => None,
            };
            pending.clear();
            last_comment.clear();
            continue;
        }
        if shell != Some(true) {
            continue;
        }
        let part = raw.trim();
        if part.is_empty() {
            last_comment.clear();
            continue;
        }
        if part.starts_with('#') && pending.is_empty() {
            last_comment.push_str(part);
            last_comment.push(' ');
            continue;
        }
        let joined = if pending.is_empty() {
            part.to_string()
        } else {
            format!("{pending} {part}")
        };
        if let Some(head) = joined.strip_suffix('\\') {
            pending = head.trim_end().to_string();
            continue;
        }
        pending.clear();
        let cmd = joined.split('#').next().unwrap_or(&joined).trim();
        if cmd.starts_with("fa ") {
            checked += 1;
            if let Some(err) = unregistered(reg, cmd) {
                assert!(
                    last_comment.contains("fa-") || joined.contains("fa-"),
                    "unregistered target-state command `{cmd}` below `## TL;DR` must carry a target bead id (`fa-…`): {err}"
                );
            }
        }
        last_comment.clear();
    }
    assert!(checked >= 10, "expected >= 10 `fa` lines below ## TL;DR, found {checked}");
}
