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
    let argv: Vec<String> = words(line).into_iter().skip(1).collect();
    let rest = reg.expand_alias(&argv);
    let Some(verb) = reg.verb(rest.first()?) else {
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
        fa tb --period FY2026-P03 --json\nfa conjure --party ACME\n\
        fa verify nonsense --json\nfa tb --period FY2026-P03 \\\n  --no-such-flag --json\n```\n\n\
        ```rust\nfa not shell\n```\n\n## TL;DR\n\n```bash\nfa conjure --target-state\n```\n";
    let lines = present_tense_lines(planted);
    assert_eq!(
        lines,
        [
            "fa tb --period FY2026-P03 --json",
            "fa conjure --party ACME",
            "fa verify nonsense --json",
            "fa tb --period FY2026-P03 --no-such-flag --json",
        ]
    );
    let verdicts: Vec<Option<String>> = lines.iter().map(|l| unregistered(reg, l)).collect();
    assert_eq!(verdicts[0], None);
    for (verdict, names) in
        verdicts[1..]
            .iter()
            .zip(["`conjure`", "subcommands", "`--no-such-flag`"])
    {
        assert!(
            verdict.as_deref().is_some_and(|v| v.contains(names)),
            "{verdict:?} should name {names}"
        );
    }
}

/// Phrases the `case` docs carried while Restatement posting waited on
/// fa-651f (H12, fa-yugf.88). Restatement cases post now
/// (`a_restatement_case_restates_a_closed_period_from_the_cli`).
const STALE_CASE_CLAIMS: [&str; 4] = [
    "entries are refused with FA-REF-178",
    "This build posts PriorPeriodAdjustment and Revision cases",
    "a PriorPeriodAdjustment or Revision case's entries",
    "Restatement posting waits",
];

fn stale_case_posting_claims(text: &str) -> Vec<&'static str> {
    STALE_CASE_CLAIMS
        .iter()
        .copied()
        .filter(|p| text.contains(p))
        .collect()
}

#[test]
fn case_docs_name_every_postable_kind_and_make_no_stale_posting_claim() {
    let reg = registry().expect("verbs.toml");
    let case = reg.verb("case").expect("the case verb");
    let post = case
        .usage
        .iter()
        .find(|u| u.starts_with("case post"))
        .expect("a case post usage line");
    let posts = post
        .split("This build posts ")
        .nth(1)
        .and_then(|rest| rest.split(" cases").next())
        .expect("the case post usage says which kinds this build posts");
    for kind in fa_journal::case::CaseKind::ALL {
        // A PolicyChangeRetrospective case's entries are Restatement entries;
        // no test posts one yet (H13, fa-yugf.93), so the usage names it
        // separately rather than claiming it.
        if fa_journal::case::posting_class(kind).is_some()
            && kind != fa_journal::case::CaseKind::PolicyChangeRetrospective
        {
            let name = format!("{kind:?}");
            assert!(posts.contains(&name), "{name} missing from: {posts}");
        }
    }
    let surfaces = [
        ("case post usage", post.as_str()),
        ("case summary", case.summary.as_str()),
        ("README", README.split("## TL;DR").next().unwrap_or(README)),
    ];
    for (what, text) in surfaces {
        let stale = stale_case_posting_claims(text);
        assert!(stale.is_empty(), "{what}: {stale:?}");
    }
    // The planted negative: every surface as it stood at 8196f5e40 is caught.
    let old_usage = "This build posts PriorPeriodAdjustment and Revision cases: a Revision case's scenario plans each Revision; a Restatement case's entries are refused with FA-REF-178.)";
    assert_eq!(
        stale_case_posting_claims(old_usage),
        [
            "entries are refused with FA-REF-178",
            "This build posts PriorPeriodAdjustment and Revision cases"
        ]
    );
    let old_summary = "approve its effect manifest under dual control, post a PriorPeriodAdjustment or Revision case's entries in one batch,";
    assert_eq!(
        stale_case_posting_claims(old_summary),
        ["a PriorPeriodAdjustment or Revision case's entries"]
    );
    let old_readme = "PriorPeriodAdjustment and Revision cases post their entries (Restatement posting waits on its SoD rule's session lineage, `fa-651f`).";
    assert_eq!(
        stale_case_posting_claims(old_readme),
        ["Restatement posting waits"]
    );
}

/// The `--scenario` list in a `demo init` usage line, split on `|`.
fn demo_usage_scenarios(usage: &str) -> Option<Vec<String>> {
    let start = usage.find("--scenario ")? + "--scenario ".len();
    let end = start + usage[start..].find(']')?;
    Some(usage[start..end].split('|').map(str::to_string).collect())
}

#[test]
fn demo_usage_names_exactly_the_scenarios_fa_demo_parses() {
    // H3 (fa-yugf.84): the usage once listed five scenarios `Scenario::parse`
    // rejects (saas, manufacturing, nonprofit, holding, crypto) and omitted
    // ghost-payroll. An agent follows usage text literally, so the registry's
    // list must be exactly the parser's.
    let names: Vec<&str> = fa_demo::Scenario::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        names,
        fa_demo::SCENARIO_NAMES,
        "SCENARIO_NAMES is Scenario::ALL"
    );
    let reg = registry().expect("verbs.toml");
    let demo = reg.verb("demo").expect("the demo verb");
    let init = demo
        .usage
        .iter()
        .find(|u| u.starts_with("demo init"))
        .expect("a demo init usage line");
    let listed = demo_usage_scenarios(init).expect("a --scenario list");
    assert_eq!(
        listed,
        fa_demo::SCENARIO_NAMES,
        "verbs.toml demo usage: {init}"
    );
    for name in &listed {
        assert!(fa_demo::Scenario::parse(name).is_some(), "{name} parses");
    }
    // The planted negative: the stale list is caught, naming what fails.
    let stale = "demo init [--scenario retail|saas|manufacturing|nonprofit|holding|crypto|bank|ponzi|shell-network|worldcom|channel-stuffing] [--seed <N>]";
    let stale_names = demo_usage_scenarios(stale).expect("the stale list parses");
    let rejected: Vec<&String> = stale_names
        .iter()
        .filter(|n| fa_demo::Scenario::parse(n).is_none())
        .collect();
    assert_eq!(
        rejected,
        ["saas", "manufacturing", "nonprofit", "holding", "crypto"]
    );
    assert_ne!(
        stale_names,
        fa_demo::SCENARIO_NAMES,
        "ghost-payroll was missing"
    );
}

#[test]
fn every_command_the_generated_demo_readme_prints_is_registered() {
    // `fa demo init` writes a README.md telling its reader what to run next.
    // Those lines are product output and get the same registry check as the
    // README's own; the generator once printed `fa procedure run … --period`,
    // a flag the procedure verb does not accept.
    // Retail, and the scenarios that add party-level commands (fa-b6xs).
    let reg = registry().expect("verbs.toml");
    for scenario in ["retail", "shell-network", "ponzi"] {
        let book = fixture().join(format!("demo-{scenario}"));
        let init = Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&book)
            .args([
                "demo",
                "init",
                "--scenario",
                scenario,
                "--seed",
                "7",
                "--json",
            ])
            .env_remove("FA_BOOK")
            .output()
            .expect("run fa demo init");
        assert_eq!(
            init.status.code(),
            Some(0),
            "{scenario}: {}\n{}",
            String::from_utf8_lossy(&init.stdout),
            String::from_utf8_lossy(&init.stderr)
        );
        let readme = std::fs::read_to_string(book.join("README.md")).expect("the demo README");
        let lines: Vec<&str> = readme
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("fa "))
            .collect();
        assert!(
            lines.len() >= 10 && lines.iter().any(|l| l.starts_with("fa procedure run ")),
            "{scenario}: the demo README's commands are not vacuous: {lines:#?}"
        );
        let wrong: Vec<String> = lines.iter().filter_map(|l| unregistered(reg, l)).collect();
        assert!(wrong.is_empty(), "{scenario}: {wrong:#?}");
    }
    // The planted negative: the line the generator used to print is named.
    let stale = "fa procedure run duplicates.same_same_same --period FY2026-P03 --book . --json";
    assert!(
        unregistered(reg, stale).is_some_and(|why| why.contains("`--period`")),
        "{stale}"
    );
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
    assert!(
        checked >= 10,
        "expected >= 10 `fa` lines below ## TL;DR, found {checked}"
    );
}

fn has_evidence_minimum_phrase(text: &str) -> bool {
    text.contains("presence and kind, not content")
        || text.contains("presence and kind, not what a document says")
}

fn check_evidence_minimum_surfaces(
    readme_above_tldr: &str,
    catalog_cites: &[(&str, &str)],
) -> Vec<String> {
    let mut missing = Vec::new();
    if !has_evidence_minimum_phrase(readme_above_tldr) {
        missing.push(
            "README above `## TL;DR` lacks the evidence-minimum limit (`presence and kind, not content`)"
                .to_string(),
        );
    }
    for (code, cite) in catalog_cites {
        if !has_evidence_minimum_phrase(cite) {
            missing.push(format!(
                "`{code}` lacks the evidence-minimum limit (`presence and kind, not content`); current cite: `{cite}`"
            ));
        }
    }
    missing
}

#[test]
fn evidence_minimum_docs_state_presence_and_kind_not_content() {
    let (above_tldr, _) = README
        .split_once("\n## TL;DR\n")
        .expect("README has a `## TL;DR` heading");
    let mut cites = Vec::new();
    for code in ["FA-REF-080", "FA-REF-086"] {
        let out = Command::new(env!("CARGO_BIN_EXE_fa"))
            .args(["explain", "refusal", code, "--json", "--no-color"])
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .output()
            .expect("run fa explain refusal");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{code}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).expect("utf-8");
        let last = stdout.lines().last().expect("one robot line");
        let parsed = json::parse(last).expect("valid JSON");
        let cite = parsed
            .get("data")
            .and_then(|d| d.get("cite"))
            .and_then(json::Json::as_str)
            .expect("data.cite string")
            .to_string();
        cites.push((code, cite));
    }
    let cite_refs: Vec<(&str, &str)> = cites.iter().map(|(c, s)| (*c, s.as_str())).collect();
    let missing = check_evidence_minimum_surfaces(above_tldr, &cite_refs);
    assert!(missing.is_empty(), "{missing:#?}");
}

#[test]
fn evidence_minimum_phrase_check_fails_without_the_sentence() {
    let (above_tldr, _) = README
        .split_once("\n## TL;DR\n")
        .expect("README has a `## TL;DR` heading");
    let stripped_readme = above_tldr.replace("presence and kind, not content", "");
    let stripped_cites = [
        (
            "FA-REF-080",
            "registries/evidence_policy.toml [[minimum]] class = \"{class}\" (FA-INV-05 evidence-minimum)",
        ),
        (
            "FA-REF-086",
            "plan §9.3 (self-sourced evidence: AgentUpload, Generated; it counts once an approver other than the uploader records a Reviewed attestation)",
        ),
    ];
    let missing = check_evidence_minimum_surfaces(&stripped_readme, &stripped_cites);
    assert_eq!(missing.len(), 3, "{missing:#?}");
    assert!(
        missing[0].contains("README above `## TL;DR`"),
        "{missing:#?}"
    );
    assert!(missing[1].contains("`FA-REF-080`"), "{missing:#?}");
    assert!(missing[2].contains("`FA-REF-086`"), "{missing:#?}");
}
