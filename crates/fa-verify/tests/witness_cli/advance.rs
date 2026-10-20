//! Retained-pin binding and continuity through the real executable.

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::checkpoint::witness::{
    MAX_WITNESS_CONSISTENCY_BYTES, MAX_WITNESSED_CHECKPOINT_BYTES,
};

use super::{args, decode, fixture, hex, key, result, retain, run, set};

fn vector(name: &str) -> Vec<u8> {
    decode(
        include_str!("../fixtures/checkpoint_witness_advance_v1.txt"),
        name,
    )
}

fn body(bytes: &[u8]) -> [u8; 32] {
    // Simulate the independently retained digest of a previously accepted
    // checkpoint. The CLI must never learn this expectation from its input.
    fa_verify::verify_checkpoint(bytes, &[key("publisher")])
        .unwrap()
        .body_digest
}

fn invocation(previous: &[u8], candidate: &[u8], proof: &[u8]) -> (Vec<OsString>, PathBuf) {
    let (mut input, dir) = args(candidate);
    std::fs::write(dir.join("previous"), previous).unwrap();
    std::fs::write(dir.join("consistency"), proof).unwrap();
    input.extend([
        "--previous".into(),
        dir.join("previous").into_os_string(),
        "--expect-previous-body".into(),
        hex(&body(previous)).into(),
        "--consistency".into(),
        dir.join("consistency").into_os_string(),
    ]);
    (input, dir)
}

#[test]
fn advancement_checks_the_independent_pin_without_overwriting_either_artifact() {
    let old = fixture("initial");
    let next = vector("extended");
    let proof = vector("extend_proof");
    let (input, dir) = invocation(&old, &next, &proof);
    let report = result(run(&input), 0);
    for field in [
        "\"continuity\":\"advanced\"",
        "\"continuity_scope\":\"consistency\"",
        "\"through_seq\":\"9\"",
        "\"leaf_count\":\"2\"",
        "previous_body_matches_retained_pin",
        "previous_publisher_and_quorum",
        "same_recipient_policy",
    ] {
        assert!(report.contains(field), "{field}: {report}");
    }
    assert!(report.contains(&hex(&body(&old))));
    assert!(report.contains(&hex(&body(&next))));
    for (file, expected) in [
        ("previous", old),
        ("candidate", next),
        ("consistency", proof),
    ] {
        assert_eq!(std::fs::read(dir.join(file)).unwrap(), expected);
    }
    assert_eq!(result(run(&input), 0), report);
    let mut human = input;
    human.retain(|arg| arg != "--json");
    let output = run(&human);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Continuity: advanced (scope: consistency)"));
    assert!(text.contains("Global freshness was not checked"));
    assert!(text.contains("No pin was written"));
}

#[test]
fn identical_bodies_with_different_sufficient_signatures_are_unchanged() {
    let all = fixture("initial");
    let first = retain(&all, &["publisher", "witness_a", "witness_b"]);
    let next = retain(&all, &["publisher", "witness_b", "witness_c"]);
    assert_ne!(first, next);
    assert_eq!(body(&first), body(&next));
    let (input, _) = invocation(&first, &next, &vector("same_proof"));
    let report = result(run(&input), 0);
    assert!(report.contains("\"continuity\":\"unchanged\""));
    assert!(report.contains(&hex(&body(&first))));
}

#[test]
fn valid_signatures_do_not_excuse_rollback_forks_or_same_sequence_equivocation() {
    let initial = fixture("initial");
    let extended = vector("extended");
    for (previous, candidate, proof) in [
        (extended.clone(), initial.clone(), vector("rollback_proof")),
        (
            extended.clone(),
            vector("regression"),
            vector("regression_proof"),
        ),
        (initial.clone(), vector("fork"), vector("fork_proof")),
        (
            initial.clone(),
            vector("changed_state"),
            vector("same_proof"),
        ),
        (
            initial.clone(),
            vector("changed_index"),
            vector("same_proof"),
        ),
        (
            initial.clone(),
            vector("changed_chain"),
            vector("same_proof"),
        ),
        (initial, extended, vector("same_proof")),
    ] {
        assert!(fa_verify::verify_checkpoint(&candidate, &[key("publisher")]).is_ok());
        let (input, _) = invocation(&previous, &candidate, &proof);
        result(run(&input), 8);
    }
}

#[test]
fn substituting_a_genuine_previous_file_cannot_reset_the_independent_pin() {
    let (mut input, dir) = invocation(
        &fixture("initial"),
        &vector("extended"),
        &vector("extend_proof"),
    );
    result(run(&input), 0);
    // An older but genuinely signed checkpoint satisfies the same witness
    // policy. Its signatures alone cannot make it the retained baseline.
    std::fs::write(dir.join("previous"), vector("empty")).unwrap();
    set(
        &mut input,
        "--checkpoint",
        dir.join("candidate-not-opened").into_os_string(),
    );
    set(
        &mut input,
        "--consistency",
        dir.join("proof-not-opened").into_os_string(),
    );
    let error = result(run(&input), 8); // not exit 5 from the absent later files
    assert!(error.contains("independently retained body digest"));
}

#[test]
fn incomplete_or_duplicate_pin_arguments_never_fall_back_to_quorum_only() {
    let (mut input, dir) = invocation(
        &fixture("initial"),
        &vector("extended"),
        &vector("extend_proof"),
    );
    set(
        &mut input,
        "--previous",
        dir.join("not-opened").into_os_string(),
    );
    for flag in ["--previous", "--expect-previous-body", "--consistency"] {
        let index = input.iter().position(|arg| arg == flag).unwrap();
        let mut missing = input.clone();
        drop(missing.drain(index..index + 2));
        result(run(&missing), 2);
        let mut repeated = input.clone();
        repeated.extend_from_slice(&input[index..index + 2]);
        result(run(&repeated), 2);
    }
    // Every nonempty partial combination refuses, not only missing one flag.
    let flags = ["--previous", "--expect-previous-body", "--consistency"];
    for mask in 1u8..7 {
        let mut partial = input.clone();
        for (bit, flag) in flags.iter().enumerate() {
            if mask & (1 << bit) == 0 {
                let index = partial.iter().position(|arg| arg == *flag).unwrap();
                drop(partial.drain(index..index + 2));
            }
        }
        result(run(&partial), 2);
    }
    for value in ["ab", &"g".repeat(64), &"é".repeat(32)] {
        let mut invalid = input.clone();
        set(&mut invalid, "--expect-previous-body", value);
        result(run(&invalid), 2);
    }
    // Even a no-op requires the existing exact consistency frame.
    let (input, _) = invocation(&fixture("initial"), &fixture("initial"), &[]);
    result(run(&input), 8);
}

#[test]
fn both_previous_and_candidate_must_satisfy_the_same_complete_policy() {
    let initial = fixture("initial");
    let extended = vector("extended");
    let weak_previous = retain(&initial, &["publisher", "witness_a", "outsider"]);
    let weak_next = retain(&extended, &["publisher", "witness_a", "outsider"]);
    for (previous, candidate) in [
        (weak_previous, extended.clone()),
        (initial.clone(), weak_next),
        (initial.clone(), fixture("other_policy")),
        (initial, fixture("missing_policy")),
    ] {
        let (input, _) = invocation(&previous, &candidate, &vector("extend_proof"));
        result(run(&input), 8);
    }
}

#[test]
fn empty_extension_and_later_same_tree_work_but_bounded_bad_proofs_do_not() {
    for (previous, candidate, proof) in [
        (vector("empty"), fixture("initial"), vector("empty_proof")),
        (
            fixture("initial"),
            vector("later_same_tree"),
            vector("later_same_tree_proof"),
        ),
    ] {
        let (input, _) = invocation(&previous, &candidate, &proof);
        assert!(result(run(&input), 0).contains("\"continuity\":\"advanced\""));
    }
    let proof = vector("extend_proof");
    let (input, dir) = invocation(&fixture("initial"), &vector("extended"), &proof);
    for end in [0, 1, proof.len() - 1] {
        std::fs::write(dir.join("consistency"), &proof[..end]).unwrap();
        result(run(&input), 8);
    }
    let mut trailing = proof;
    trailing.push(0);
    std::fs::write(dir.join("consistency"), trailing).unwrap();
    result(run(&input), 8);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("consistency"))
        .unwrap();
    file.set_len(MAX_WITNESS_CONSISTENCY_BYTES as u64 + 1)
        .unwrap();
    assert!(result(run(&input), 8).contains("byte bound"));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("previous"))
        .unwrap();
    file.set_len(MAX_WITNESSED_CHECKPOINT_BYTES as u64 + 1)
        .unwrap();
    assert!(result(run(&input), 8).contains("byte bound"));
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "macOS filesystems refuse non-UTF-8 file names (EILSEQ); exercised on Linux hosts"
)]
fn pin_and_proof_paths_preserve_non_utf8_bytes_while_the_expected_digest_does_not() {
    use std::os::unix::ffi::OsStringExt;
    let (mut input, dir) = invocation(
        &fixture("initial"),
        &vector("extended"),
        &vector("extend_proof"),
    );
    for (flag, name) in [("--previous", "previous"), ("--consistency", "consistency")] {
        let path = dir.join(OsString::from_vec(
            format!("{name}-").bytes().chain([255]).collect(),
        ));
        std::fs::copy(dir.join(name), &path).unwrap();
        set(&mut input, flag, path.into_os_string());
    }
    result(run(&input), 0);
    set(
        &mut input,
        "--expect-previous-body",
        OsString::from_vec(vec![255]),
    );
    result(run(&input), 2);
}
