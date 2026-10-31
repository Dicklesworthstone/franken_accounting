//! Recipient-selected access-attempt extraction over existing native artifacts.

use super::{Args, Check, Json, Read, Usage, Verdict, h, int, key, load, n, s, subject, usage};
use crate::access_log::{
    AccessLogRequest, MAX_ACCESS_TRUSTED_KEYS, SCOPE_ACCESS_LOG, VerifiedAccessLog,
    verify_access_log,
};

pub(super) fn run(args: &Args, read: Read<'_>) -> Result<Vec<Check>, Usage> {
    // Validate every option before opening any artifact.
    let prefix_path = subject(args, "a native v2 complete-prefix file")?;
    let state_path = args.one("--state").ok_or_else(|| {
        usage(
            "access-log needs --state",
            "export the canonical state named by the signed checkpoint's state_oid",
        )
    })?;
    let checkpoint_path = args.one("--checkpoint").ok_or_else(|| {
        usage(
            "access-log needs --checkpoint",
            "supply the signed checkpoint for that exact state and prefix",
        )
    })?;
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
    let prefix = load(read, prefix_path, args.hex)?;
    let state = load(read, state_path, args.hex)?;
    let checkpoint = load(read, checkpoint_path, args.hex)?;
    let check = match verify_access_log(&prefix, &state, &checkpoint, &keys, &request) {
        Ok(log) => checked(log),
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

fn checked(log: VerifiedAccessLog) -> Check {
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
