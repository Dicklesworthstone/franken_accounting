//! Recipient-selected access-attempt extraction over existing native artifacts.

use super::{Args, Check, Json, Read, Usage, Verdict, h, int, key, load, n, s, subject, usage};
use crate::access_log::{
    ACCESS_LOG_PROOF_FORMAT, AccessLogExpectation, AccessLogRequest, MAX_ACCESS_TRUSTED_KEYS,
    SCOPE_ACCESS_LOG, VerifiedAccessLog, verify_access_log, verify_access_log_expected,
    verify_access_log_proof,
};

pub(super) fn run(args: &Args, read: Read<'_>) -> Result<Vec<Check>, Usage> {
    // Validate every option before opening any artifact. Separate components
    // retain their original grammar; a portable proof requires source identity.
    let path = subject(
        args,
        "a portable access-log proof or native v2 complete-prefix file",
    )?;
    let components = match (args.one("--state"), args.one("--checkpoint")) {
        (Some(state), Some(checkpoint)) => Some((state, checkpoint)),
        (None, None) => None,
        _ => {
            return Err(usage(
                "access-log requires --state and --checkpoint together",
                "supply both for a raw prefix, or omit both for a portable access-log proof",
            ));
        }
    };
    let expected = match (
        args.one("--book"),
        args.one("--branch"),
        args.one("--expect-checkpoint"),
    ) {
        (None, None, None) if components.is_some() => None,
        (Some(book), Some(branch), checkpoint) => Some(AccessLogExpectation {
            book_id: identity_hex(book, "--book")?,
            branch_id: identity_hex(branch, "--branch")?,
            checkpoint_oid: checkpoint
                .map(|value| identity_hex(value, "--expect-checkpoint"))
                .transpose()?,
        }),
        _ => {
            return Err(usage(
                "access-log needs the recipient's --book and --branch",
                "supply both as 32 hex digits; optionally pin the signed checkpoint with --expect-checkpoint <64 hex>",
            ));
        }
    };
    let raw_keys = args.all("--key");
    if raw_keys.is_empty() || raw_keys.len() > MAX_ACCESS_TRUSTED_KEYS {
        return Err(usage(
            "access-log requires 1..=64 recipient-trusted signing keys",
            "pass each trusted Ed25519 public key with --key <64 hex>",
        ));
    }
    let keys = raw_keys
        .into_iter()
        .map(key)
        .collect::<Result<Vec<_>, _>>()?;
    let after_seq = int::<u64>(args, "--after-seq", "access-log")?;
    let through_seq = int::<u64>(args, "--through-seq", "access-log")?;
    if after_seq > through_seq {
        return Err(usage(
            "access-log --after-seq exceeds --through-seq",
            "supply the recording interval (after_seq, through_seq] you want verified",
        ));
    }
    let principal = args
        .one("--reader")
        .map(|value| {
            let digits = value.strip_prefix("0x").unwrap_or(value);
            if digits.len() != 32 || !digits.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(usage(
                    "access-log --reader must be a principal ID of exactly 32 hex digits",
                    "use the recorded principal ID (optional 0x prefix), not a display name",
                ));
            }
            u128::from_str_radix(digits, 16).map_err(|_| {
                usage(
                    "access-log --reader is not a principal ID",
                    "supply exactly 32 hex digits, optionally prefixed by 0x",
                )
            })
        })
        .transpose()?;
    let request = AccessLogRequest {
        after_seq,
        through_seq,
        principal,
    };
    let input = load(read, path, args.hex)?;
    let result = if let Some((state_path, checkpoint_path)) = components {
        if crate::codec::Reader::new(&input)
            .bytes(64, "proof.format")
            .is_ok_and(|format| format == ACCESS_LOG_PROOF_FORMAT)
        {
            return Err(usage(
                "a portable access-log proof already contains its state and signed checkpoint",
                "omit --state and --checkpoint; supply your expected --book and --branch",
            ));
        }
        let state = load(read, state_path, args.hex)?;
        let checkpoint = load(read, checkpoint_path, args.hex)?;
        match expected.as_ref() {
            Some(expected) => {
                verify_access_log_expected(&input, &state, &checkpoint, &keys, &request, expected)
            }
            None => verify_access_log(&input, &state, &checkpoint, &keys, &request),
        }
    } else {
        let expected = expected.as_ref().ok_or_else(|| {
            usage(
                "portable access-log proofs require an independently selected source",
                "supply --book and --branch as 32 hex digits",
            )
        })?;
        verify_access_log_proof(&input, &keys, &request, expected)
    };
    let check = match result {
        Ok(log) => checked(log, expected.as_ref()),
        Err(error) => Check {
            name: "access_log",
            scope: SCOPE_ACCESS_LOG,
            verdict: Verdict::Fail,
            detail: vec![("predicate", s(error.predicate))],
            reason: Some(error.to_string()),
        },
    };
    Ok(vec![check])
}

fn identity_hex<const N: usize>(value: &str, flag: &str) -> Result<[u8; N], Usage> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    let invalid = || {
        usage(
            format!("access-log {flag} requires exactly {} hex digits", N * 2),
            "supply the independently retained identity, optionally prefixed by 0x",
        )
    };
    if digits.len() != N * 2 || !digits.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut bytes = [0; N];
    for (byte, pair) in bytes.iter_mut().zip(digits.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).map_err(|_| invalid())?;
        *byte = u8::from_str_radix(text, 16).map_err(|_| invalid())?;
    }
    Ok(bytes)
}

fn checked(log: VerifiedAccessLog, expected: Option<&AccessLogExpectation>) -> Check {
    let events = log
        .events
        .iter()
        .map(|event| {
            Json::Obj(vec![
                ("recorded_at", n(event.recorded_at)),
                (
                    "within_commit_ordinal",
                    n(u64::from(event.within_commit_ordinal)),
                ),
                ("record_digest", h(&event.record_digest)),
                ("principal", s(format!("{:032x}", event.principal))),
                ("principal_name", s(&event.principal_name)),
                ("capability_commitment", h(&event.capability_commitment)),
                ("ops", Json::List(event.ops.iter().map(s).collect())),
                ("command", s(&event.command)),
                ("request_digest", h(&event.request_digest)),
                ("observed_at", n(event.observed_at)),
            ])
        })
        .collect();
    Check::pass(
        "access_log",
        log.scope,
        vec![
            ("book_id", h(&log.checkpoint.checkpoint.book_id)),
            ("branch_id", h(&log.checkpoint.checkpoint.branch_id)),
            ("checkpoint_oid", h(&log.checkpoint.oid)),
            ("state_oid", h(&log.checkpoint.state_oid)),
            (
                "source_selection",
                s(if expected.is_some() {
                    "recipient_bound"
                } else {
                    "signed_identity_reported"
                }),
            ),
            (
                "expected_checkpoint_oid",
                expected
                    .and_then(|expected| expected.checkpoint_oid)
                    .map_or(Json::Null, |oid| h(&oid)),
            ),
            (
                "signed_through_seq",
                n(log.checkpoint.checkpoint.through_seq),
            ),
            (
                "signed_by",
                Json::List(log.checkpoint.signed_by.iter().map(|key| h(key)).collect()),
            ),
            ("access_after_seq", n(log.access_after_seq)),
            ("after_seq", n(log.request.after_seq)),
            ("through_seq", n(log.request.through_seq)),
            (
                "reader",
                log.request
                    .principal
                    .map_or(Json::Null, |id| s(format!("{id:032x}"))),
            ),
            ("checked_records", n(log.checked_records as u64)),
            ("record_check", s("recomputed")),
            ("coverage", s("signed_state_boundary")),
            ("meaning", s("recorded_pre_disclosure_attempts")),
            ("count", n(log.events.len() as u64)),
            ("events", Json::List(events)),
        ],
    )
}
