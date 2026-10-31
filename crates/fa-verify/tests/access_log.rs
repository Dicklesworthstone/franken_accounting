//! Public API and executable checks for authenticated access-attempt extracts.
//! The fixtures use the existing canonical wires and real Ed25519 signatures.

use fa_verify::access_log::{
    AccessLogRequest, MAX_ACCESS_CHECKPOINT_BYTES, MAX_ACCESS_STATE_BYTES, MAX_ACCESS_TRUSTED_KEYS,
    SCOPE_ACCESS_LOG, VerifiedAccessLog, verify_access_log,
};
use fa_verify::codec::Writer;
use fa_verify::envelope::{LeafEnvelope, MAX_RECORD_BYTES};
use fa_verify::proof::production::derivation::{MAX_PREFIX_PROOF_BYTES, PREFIX_FORMAT_V2};
use fa_verify::{Checkpoint, verify_checkpoint, verify_state};

const VECTORS: &str = include_str!("fixtures/access_log_v1.txt");

// A fixture-local cursor keeps the production decoder private. It only reads
// the pinned trusted fixture to construct adversarial proof variants.
struct FixtureReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> FixtureReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], &'static str> {
        let end = self.offset.checked_add(count).ok_or("fixture overflow")?;
        let value = self.data.get(self.offset..end).ok_or("truncated fixture")?;
        self.offset = end;
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self, _label: &str) -> Result<[u8; N], &'static str> {
        self.take(N)?.try_into().map_err(|_| "fixture width")
    }
    fn u32(&mut self, label: &str) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.fixed(label)?))
    }
    fn u64(&mut self, label: &str) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(self.fixed(label)?))
    }
    fn count(&mut self, max: usize, _minimum: usize, label: &str) -> Result<usize, &'static str> {
        let count = self.u32(label)? as usize;
        if count > max {
            return Err("fixture count");
        }
        Ok(count)
    }
    fn bytes(&mut self, max: usize, label: &str) -> Result<&'a [u8], &'static str> {
        let count = self.count(max, 1, label)?;
        self.take(count)
    }
    fn finish(&self, _label: &str) -> Result<(), &'static str> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err("trailing fixture bytes")
        }
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn vector(name: &str) -> Vec<u8> {
    unhex(
        VECTORS
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
            .expect("pinned access-log vector"),
    )
}

fn trusted_key() -> [u8; 32] {
    vector("public_key").try_into().unwrap()
}

fn request() -> AccessLogRequest {
    AccessLogRequest {
        after_seq: 10,
        through_seq: 15,
        principal: None,
    }
}

fn verify(selected: AccessLogRequest) -> Result<VerifiedAccessLog, fa_verify::AccessLogError> {
    verify_access_log(
        &vector("prefix"),
        &vector("state"),
        &vector("checkpoint"),
        &[trusted_key()],
        &selected,
    )
}

struct Parts {
    checkpoint: Checkpoint,
    envelopes: Vec<LeafEnvelope>,
    records: Vec<(u64, u32, Vec<u8>)>,
}

fn parts() -> Parts {
    let bytes = vector("prefix");
    let mut r = FixtureReader::new(&bytes);
    assert_eq!(r.bytes(64, "format").unwrap(), PREFIX_FORMAT_V2);
    let checkpoint = Checkpoint::decode(&r.fixed::<80>("checkpoint").unwrap()).unwrap();
    let count = r.count(16, 4, "envelopes").unwrap();
    let envelopes = (0..count)
        .map(|_| LeafEnvelope::decode(r.bytes(MAX_RECORD_BYTES, "envelope").unwrap()).unwrap())
        .collect();
    let count = r.count(16, 16, "records").unwrap();
    let records = (0..count)
        .map(|_| {
            (
                r.u64("index").unwrap(),
                r.u32("split").unwrap(),
                r.bytes(MAX_RECORD_BYTES, "payload").unwrap().to_vec(),
            )
        })
        .collect();
    r.finish("fixture").unwrap();
    Parts {
        checkpoint,
        envelopes,
        records,
    }
}

impl Parts {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(PREFIX_FORMAT_V2)
            .fixed(&self.checkpoint.encode())
            .count(self.envelopes.len());
        for envelope in &self.envelopes {
            w.bytes(&envelope.encode());
        }
        w.count(self.records.len());
        for (index, split, payload) in &self.records {
            w.u64(*index).u32(*split).bytes(payload);
        }
        w.buf
    }
}

fn check_prefix(prefix: &[u8], selected: &AccessLogRequest) -> fa_verify::AccessLogError {
    verify_access_log(
        prefix,
        &vector("state"),
        &vector("checkpoint"),
        &[trusted_key()],
        selected,
    )
    .unwrap_err()
}

#[test]
fn real_signed_fixture_extracts_every_recorded_attempt_in_journal_order() {
    let log = verify(request()).unwrap();
    assert_eq!(log.scope, SCOPE_ACCESS_LOG);
    assert_eq!(log.access_after_seq, 10);
    assert_eq!(
        log.checked_records, 5,
        "the non-access entry was checked too"
    );
    assert_eq!(log.request, request());
    assert_eq!(log.events.len(), 4);
    assert_eq!(
        log.events
            .iter()
            .map(|event| (
                event.recorded_at,
                event.within_commit_ordinal,
                event.principal,
                event.observed_at
            ))
            .collect::<Vec<_>>(),
        vec![
            (11, 0, 7, 9),
            (12, 0, 8, 10),
            (12, 1, 7, 11),
            (15, 0, 7, 14)
        ]
    );
    let first = &log.events[0];
    assert_eq!(first.principal_name, "auditor");
    assert_eq!(first.ops, ["produce", "read"]);
    assert_eq!(first.command, "tb");
    assert_eq!(first.capability_commitment, [3; 32]);
    assert_eq!(first.request_digest, [4; 32]);
    assert_eq!(first.record_digest, parts().envelopes[1].record_digest);
    assert_eq!(
        log.checkpoint.state_oid,
        verify_state(&vector("state")).unwrap().oid
    );
    assert_eq!(log.checkpoint.signed_by.len(), 1);
}

#[test]
fn recipient_selection_uses_recording_sequence_and_principal_id_not_name_or_observed_time() {
    let selected = AccessLogRequest {
        after_seq: 11,
        through_seq: 12,
        principal: Some(7),
    };
    let log = verify(selected).unwrap();
    assert_eq!(log.request, selected);
    assert_eq!(log.checked_records, 5);
    assert_eq!(log.events.len(), 1);
    assert_eq!(log.events[0].recorded_at, 12);
    assert_eq!(log.events[0].within_commit_ordinal, 1);
    assert_eq!(
        log.events[0].observed_at, 11,
        "selection is not by observation time"
    );
    assert_eq!(log.events[0].principal_name, "renamed-auditor");
    let other = verify(AccessLogRequest {
        principal: Some(8),
        ..request()
    })
    .unwrap();
    assert_eq!(other.events.len(), 1);
    assert_eq!(
        other.events[0].principal_name, "auditor",
        "same name is a different principal"
    );
    let all_seven = verify(AccessLogRequest {
        principal: Some(7),
        ..request()
    })
    .unwrap();
    assert_eq!(
        all_seven.events.len(),
        3,
        "renaming does not change the recorded principal ID"
    );
}

#[test]
fn empty_filtered_and_zero_width_intervals_are_complete_only_after_full_verification() {
    for selected in [
        AccessLogRequest {
            principal: Some(999),
            ..request()
        },
        AccessLogRequest {
            after_seq: 12,
            through_seq: 12,
            principal: None,
        },
    ] {
        let log = verify(selected).unwrap();
        assert!(log.events.is_empty());
        assert_eq!(log.checked_records, 5);
        assert_eq!(log.request, selected);
    }
}

#[test]
fn request_before_coverage_or_beyond_signed_horizon_is_refused_even_when_empty() {
    for selected in [
        AccessLogRequest {
            after_seq: 9,
            through_seq: 15,
            principal: None,
        },
        AccessLogRequest {
            after_seq: 9,
            through_seq: 9,
            principal: Some(999),
        },
    ] {
        assert_eq!(verify(selected).unwrap_err().predicate, "access.coverage");
    }
    for selected in [
        AccessLogRequest {
            after_seq: 12,
            through_seq: 11,
            principal: None,
        },
        AccessLogRequest {
            through_seq: 16,
            ..request()
        },
        AccessLogRequest {
            after_seq: 16,
            through_seq: 16,
            principal: Some(999),
        },
        AccessLogRequest {
            through_seq: u64::MAX,
            ..request()
        },
    ] {
        assert_eq!(verify(selected).unwrap_err().predicate, "access.selection");
    }
}

#[test]
fn signed_legacy_state_cannot_claim_access_coverage() {
    for family in ["legacy", "evidence_only"] {
        let state = vector(&format!("{family}_state"));
        let signed = vector(&format!("{family}_checkpoint"));
        assert!(verify_checkpoint(&signed, &[trusted_key()]).is_ok());
        assert_eq!(verify_state(&state).unwrap().access_after_seq, None);
        let error = verify_access_log(
            &vector("prefix"),
            &state,
            &signed,
            &[trusted_key()],
            &AccessLogRequest {
                principal: Some(999),
                ..request()
            },
        )
        .unwrap_err();
        assert_eq!(error.predicate, "access.coverage");
    }
}

#[test]
fn signed_boundary_cannot_silently_hide_an_access_leaf_at_or_before_it() {
    let error = verify_access_log(
        &vector("prefix"),
        &vector("late_boundary_state"),
        &vector("late_boundary_checkpoint"),
        &[trusted_key()],
        &AccessLogRequest {
            after_seq: 12,
            through_seq: 15,
            principal: Some(999),
        },
    )
    .unwrap_err();
    assert_eq!(error.predicate, "access.coverage");
}

#[test]
fn substituted_state_with_identical_raw_checkpoint_is_refused() {
    let mut state = vector("state");
    let boundary = state.len() - 16;
    state[boundary] = 2;
    assert_eq!(
        verify_state(&state).unwrap().checkpoint,
        verify_state(&vector("state")).unwrap().checkpoint
    );
    let error = verify_access_log(
        &vector("prefix"),
        &state,
        &vector("checkpoint"),
        &[trusted_key()],
        &request(),
    )
    .unwrap_err();
    assert_eq!(error.predicate, "access.state_binding");
}

#[test]
fn every_signed_checkpoint_coordinate_must_match_the_authenticated_state() {
    for coordinate in ["book", "branch", "through", "leaves", "root"] {
        let signed = vector(&format!("wrong_{coordinate}_checkpoint"));
        assert!(
            verify_checkpoint(&signed, &[trusted_key()]).is_ok(),
            "valid test signature"
        );
        let error = verify_access_log(
            &vector("prefix"),
            &vector("state"),
            &signed,
            &[trusted_key()],
            &request(),
        )
        .unwrap_err();
        assert_eq!(error.predicate, "access.state_binding", "{coordinate}");
    }
}

#[test]
fn unsigned_wrong_key_and_tampered_checkpoints_cannot_be_used_as_anchors() {
    let mut damaged = vector("checkpoint");
    *damaged.last_mut().unwrap() ^= 1;
    for checkpoint in [damaged, parts().checkpoint.encode().to_vec()] {
        assert_eq!(
            verify_access_log(
                &vector("prefix"),
                &vector("state"),
                &checkpoint,
                &[trusted_key()],
                &request()
            )
            .unwrap_err()
            .predicate,
            "access.checkpoint"
        );
    }
    let other_key: [u8; 32] =
        unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
            .try_into()
            .unwrap();
    assert_eq!(
        verify_access_log(
            &vector("prefix"),
            &vector("state"),
            &vector("checkpoint"),
            &[other_key],
            &request()
        )
        .unwrap_err()
        .predicate,
        "access.checkpoint"
    );
}

#[test]
fn omitted_duplicate_reordered_and_extra_records_or_envelopes_are_refused() {
    for variant in 0..7 {
        let mut proof = parts();
        match variant {
            0 => {
                proof.records.remove(2);
            }
            1 => {
                proof.envelopes.remove(2);
                proof.records.remove(2);
            }
            2 => proof.records.swap(1, 2),
            3 => proof.envelopes.swap(1, 2),
            4 => proof.records[2] = proof.records[1].clone(),
            5 => proof.records.push(proof.records[1].clone()),
            6 => proof.records[2].0 = 1,
            _ => unreachable!(),
        }
        assert_eq!(
            check_prefix(&proof.encode(), &request()).predicate,
            "access.prefix",
            "{variant}"
        );
    }
}

#[test]
fn every_payload_is_checked_even_for_unrelated_entries_and_empty_selections() {
    for selected in [
        AccessLogRequest {
            principal: Some(999),
            ..request()
        },
        AccessLogRequest {
            after_seq: 12,
            through_seq: 12,
            principal: None,
        },
        AccessLogRequest {
            principal: Some(7),
            ..request()
        },
    ] {
        for excluded in [0, 2] {
            let mut proof = parts();
            // A native entry and another principal's event are both mandatory.
            proof.records[excluded].2[0] ^= 1;
            assert_eq!(
                check_prefix(&proof.encode(), &selected).predicate,
                "access.prefix"
            );
        }
    }
}

#[test]
fn tampered_principal_book_recording_position_or_envelope_selectors_are_refused() {
    for variant in 0..5 {
        let mut proof = parts();
        match variant {
            0 => proof.records[2].2[34] = 7,
            1 => proof.records[1].2[18] ^= 1,
            2 => proof.envelopes[1].commit_seq = 10,
            3 => proof.envelopes[1].class = 2,
            4 => proof.envelopes[1].account_vids.push(7),
            _ => unreachable!(),
        }
        assert_eq!(
            check_prefix(&proof.encode(), &request()).predicate,
            "access.prefix"
        );
    }
}

#[test]
fn legacy_balance_unknown_truncated_and_trailing_prefix_formats_are_refused() {
    for format in [
        b"fa:acc-prefix-proof:v1".as_slice(),
        b"fa:acc-prefix-proof:v9".as_slice(),
        fa_verify::migration_balance::BALANCE_FORMAT_V3,
    ] {
        let mut w = Writer::default();
        w.bytes(format).fixed(&parts().checkpoint.encode());
        assert_eq!(check_prefix(&w.buf, &request()).predicate, "access.prefix");
    }
    let prefix = vector("prefix");
    for end in [0, 1, 3, 4, 24, 100, prefix.len() - 1] {
        assert_eq!(
            check_prefix(&prefix[..end], &request()).predicate,
            "access.prefix"
        );
    }
    let mut extra = prefix;
    extra.push(0);
    assert_eq!(check_prefix(&extra, &request()).predicate, "access.prefix");
}

#[test]
fn resource_bounds_and_missing_trust_are_refused_before_decoding() {
    let selected = request();
    for keys in [vec![], vec![trusted_key(); MAX_ACCESS_TRUSTED_KEYS + 1]] {
        assert_eq!(
            verify_access_log(&[], &[], &[], &keys, &selected)
                .unwrap_err()
                .predicate,
            "access.trust"
        );
    }
    for (prefix, state, checkpoint) in [
        (vec![], vec![0; MAX_ACCESS_STATE_BYTES + 1], vec![]),
        (vec![], vec![], vec![0; MAX_ACCESS_CHECKPOINT_BYTES + 1]),
        (vec![0; MAX_PREFIX_PROOF_BYTES + 1], vec![], vec![]),
    ] {
        assert_eq!(
            verify_access_log(&prefix, &state, &checkpoint, &[trusted_key()], &selected)
                .unwrap_err()
                .predicate,
            "access.bounds"
        );
    }
}

fn argv() -> Vec<String> {
    [
        "access-log",
        "prefix",
        "--state",
        "state",
        "--checkpoint",
        "checkpoint",
        "--key",
        &fa_verify::blake3::hex(&trusted_key()),
        "--after-seq",
        "10",
        "--through-seq",
        "15",
        "--json",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn cli_read(path: &str) -> std::io::Result<Vec<u8>> {
    match path {
        "prefix" | "state" | "checkpoint" => Ok(vector(path)),
        _ => panic!("unexpected read: {path}"),
    }
}

#[test]
fn cli_reports_exact_selected_rows_and_the_access_attempt_scope() {
    let mut args = argv();
    args.extend(["--reader", "00000000000000000000000000000007"].map(str::to_string));
    let output = fa_verify::cli::run(&args, &cli_read);
    assert_eq!(output.exit, 0, "{}", output.stdout);
    assert!(output.stderr.is_empty());
    for expected in [
        "\"scope\":\"access_log_complete\"",
        "\"record_check\":\"recomputed\"",
        "\"meaning\":\"recorded_pre_disclosure_attempts\"",
        "\"count\":3",
        "\"checked_records\":5",
        "\"access_after_seq\":10",
        "\"reader\":\"00000000000000000000000000000007\"",
    ] {
        assert!(
            output.stdout.contains(expected),
            "missing {expected}: {}",
            output.stdout
        );
    }
    assert!(
        !output.stdout.contains("\"command\":\"export\""),
        "same-name principal 8 is excluded"
    );
    assert_eq!(
        output,
        fa_verify::cli::run(&args, &cli_read),
        "deterministic output"
    );
}

#[test]
fn malformed_missing_duplicate_or_inapplicable_cli_options_never_open_an_input() {
    let no_read = |path: &str| -> std::io::Result<Vec<u8>> { panic!("usage error read {path}") };
    for missing in [
        "--state",
        "--checkpoint",
        "--key",
        "--after-seq",
        "--through-seq",
    ] {
        let mut args = argv();
        let index = args.iter().position(|arg| arg == missing).unwrap();
        args.drain(index..index + 2);
        assert_eq!(fa_verify::cli::run(&args, &no_read).exit, 2, "{missing}");
    }
    for extra in [
        vec!["--state", "other"],
        vec!["--after-seq", "10"],
        vec!["--reader", "auditor"],
        vec!["--reader", "0x7"],
        vec!["--reader", "0000000000000000000000000000000g"],
        vec!["--unsigned-checkpoint"],
        vec!["--account", "7"],
    ] {
        let mut args = argv();
        args.extend(extra.into_iter().map(str::to_string));
        assert_eq!(fa_verify::cli::run(&args, &no_read).exit, 2);
    }
    for (flag, value) in [
        ("--after-seq", "16"),
        ("--after-seq", "-1"),
        ("--through-seq", "18446744073709551616"),
        ("--key", "00"),
    ] {
        let mut args = argv();
        let index = args.iter().position(|arg| arg == flag).unwrap() + 1;
        args[index] = value.to_string();
        assert_eq!(
            fa_verify::cli::run(&args, &no_read).exit,
            2,
            "{flag}={value}"
        );
    }
}

#[test]
fn cli_verification_failures_and_io_failures_have_distinct_nonzero_exits() {
    let mut args = argv();
    let index = args.iter().position(|arg| arg == "--after-seq").unwrap() + 1;
    args[index] = "9".to_string();
    let output = fa_verify::cli::run(&args, &cli_read);
    assert_eq!(output.exit, 8);
    assert!(output.stdout.contains("access.coverage"));
    assert!(output.stdout.contains("\"result\":\"fail\""));
    let absent = |_path: &str| {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "absent artifact",
        ))
    };
    assert_eq!(fa_verify::cli::run(&argv(), &absent).exit, 5);
}

#[test]
fn executable_routes_proof_alias_and_hex_inputs_to_the_signed_access_verifier() {
    use std::fs;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "fa-access-log-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let prefix = dir.join("prefix");
    let state = dir.join("state");
    let checkpoint = dir.join("checkpoint");
    for (path, name) in [
        (&prefix, "prefix"),
        (&state, "state"),
        (&checkpoint, "checkpoint"),
    ] {
        fs::write(path, vector(name)).unwrap();
    }
    let command = |hex: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fa-verify"));
        cmd.arg("access-log")
            .arg("--proof")
            .arg(&prefix)
            .arg("--state")
            .arg(&state)
            .arg("--checkpoint")
            .arg(&checkpoint)
            .arg("--key")
            .arg(fa_verify::blake3::hex(&trusted_key()))
            .args([
                "--after-seq",
                "11",
                "--through-seq",
                "12",
                "--reader",
                "0x00000000000000000000000000000007",
                "--json",
            ]);
        if hex {
            cmd.arg("--hex");
        }
        cmd.output().unwrap()
    };
    let raw = command(false);
    assert!(
        raw.status.success(),
        "{}",
        String::from_utf8_lossy(&raw.stderr)
    );
    assert!(String::from_utf8_lossy(&raw.stdout).contains("\"count\":1"));
    for (path, name) in [
        (&prefix, "prefix"),
        (&state, "state"),
        (&checkpoint, "checkpoint"),
    ] {
        fs::write(path, fa_verify::blake3::hex(&vector(name))).unwrap();
    }
    let hex = command(true);
    assert!(
        hex.status.success(),
        "{}",
        String::from_utf8_lossy(&hex.stderr)
    );
    assert_eq!(raw.stdout, hex.stdout);
    // Retain these small fixtures for inspection under the repository's
    // explicit no-file-deletion rule.
}
