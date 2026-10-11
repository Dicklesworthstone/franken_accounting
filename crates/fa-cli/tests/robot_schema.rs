//! The robot-schema fixture pin (plan Appendix D; AGENTS.md "the robot-schema
//! fixture pin"; bead fa-12x): `fa robot-docs schema --json` equals
//! `registries/robot_schema/<v>.jsonl` byte for byte, where `<v>` is the
//! envelope version. A change to any event, shape, or the envelope is a
//! deliberate fixture edit reviewed with it, never a silent drift; a new
//! envelope version gets its own fixture file. `scripts/check.sh` runs this
//! target as its `robot-schema` step.

use std::process::Command;

/// The first pin, at envelope version 1.
const FIXTURE: &str = include_str!("../../../registries/robot_schema/1.jsonl");

#[test]
fn the_robot_schema_is_pinned_byte_for_byte() {
    assert_eq!(
        fa_cli::verbs::ENVELOPE_VERSION,
        1,
        "a new envelope version needs its own fixture file"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_fa"))
        .args(["robot-docs", "schema", "--json"])
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).expect("UTF-8 stdout");
    assert_eq!(stdout.lines().count(), 1, "one robot line");
    let drift = stdout
        .bytes()
        .zip(FIXTURE.bytes())
        .position(|(a, b)| a != b)
        .or_else(|| (stdout.len() != FIXTURE.len()).then(|| stdout.len().min(FIXTURE.len())));
    // Up to 60 bytes either side of `at`, widened to character boundaries.
    let around = |text: &str, at: usize| -> String {
        let mut from = at.saturating_sub(60).min(text.len());
        while !text.is_char_boundary(from) {
            from -= 1;
        }
        let mut to = (at + 60).min(text.len());
        while !text.is_char_boundary(to) {
            to += 1;
        }
        text.get(from..to).unwrap_or_default().to_string()
    };
    if drift.is_some() {
        // The binary's whole line, so the drift can be reviewed against the
        // registry change that caused it (the fixture is edited with it).
        println!("----- fa robot-docs schema --json (binary) -----\n{stdout}----- end -----");
    }
    assert!(
        drift.is_none(),
        "registries/robot_schema/1.jsonl drifts from `fa robot-docs schema --json` at byte {}:\n  binary:  …{}…\n  fixture: …{}…\nEdit the registry and the fixture together (the change is part of the contract).",
        drift.unwrap_or_default(),
        around(&stdout, drift.unwrap_or_default()),
        around(FIXTURE, drift.unwrap_or_default()),
    );
}

/// The pin is the robot line itself: the Appendix D envelope with the
/// schema under `data`, about no book.
#[test]
fn the_fixture_is_one_appendix_d_robot_line() {
    let reg = fa_cli::verbs::registry().expect("verbs.toml");
    let line = FIXTURE.strip_suffix('\n').unwrap_or(FIXTURE);
    assert!(!line.contains('\n'), "exactly one line");
    assert_eq!(reg.check_line(line), Ok("robot_schema"));
    assert!(line.contains(r#""book":null"#) && line.contains(r#""v":1"#));
}
