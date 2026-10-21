//! Offline retained-baseline plus exact-suffix index verification.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use fa_verify::checkpoint::witness::{
    MAX_WITNESS_CONSISTENCY_BYTES, MAX_WITNESSED_CHECKPOINT_BYTES, verify_witnessed_checkpoint,
};
use fa_verify::cli::Output;
use fa_verify::proof::production::{MAX_PRODUCTION_BYTES, MAX_PRODUCTION_RECORDS};
use fa_verify::scope::payloads::incremental::IncrementalPayloadIndex;
use fa_verify::scope::payloads::verify_scope_with_payload_index;
use fa_verify::scope::{ScopeClaim, ScopeReport};

use crate::{Failure, array, hex, object, quote, read_bounded};

const HELP: &str = "Incremental witnessed scope-index verification:
  fa-verify witness index --checkpoint CANDIDATE --previous RETAINED \\
    --expect-previous-body HEX64 --consistency PROOF --baseline-prefix PREFIX \\
    --expect-book HEX32 --expect-branch HEX32 --expect-policy HEX64 \\
    --publisher-key HEX64 --witness-key HEX64 [--witness-key HEX64 ...] \\
    --quorum N [--delta-record INCLUSION ...] [--json]

Optionally verify one independently selected account interval at the new root:
  --scope-proof FILE --expect-account HEX32 --expect-days FIRST:LAST
Supply all three or none. The account is an exact u128 encoded as 32 hex digits;
FIRST and LAST are inclusive signed i32 civil days, not recorded sequences.

The independently retained body digest is checked before any baseline,
candidate or delta file is opened. Both checkpoints obey the same recipient
publisher/witness policy. All trust inputs must be obtained separately from
the producer's files. The candidate cannot supply replacement keys or quorum.

PREFIX is a retained native v2 payload-complete prefix or native v3 balance
witness at the PREVIOUS checkpoint. Its entire index is verified once in this
invocation. Repeated --delta-record options supply every newly appended leaf,
in order, as existing record-bearing inclusion proofs at the NEW checkpoint.
Undated controls and evidence records are required too. Missing, extra,
reordered, envelope-only or old-sequence records fail without fallback. An
empty delta is valid only for an unchanged tree size. Late effective dates
remain valid. The candidate index is recomputed from retained plus new tuples.

No new proof or pin format is introduced. No input or retained state is written.
This executable rechecks the retained baseline each invocation; the library's
IncrementalPayloadIndex can retain it in memory between advances. Old payloads
need not be transported again, but metadata merging/root hashing is still
linear in the index. This is not a logarithmic-time or benchmark claim.

One 64 MiB budget covers previous/candidate checkpoints, baseline, consistency,
all delta records and an optional range proof. At most 4096 records may be
appended; retained index limits are 65536 leaves and 1048576 tuples. Inputs
are raw bytes, not hex text; paths may be non-UTF-8. Payloads are never printed.
Full-baseline/suffix disclosure is NOT authorized by this verification. No
freshness, economic truth, private index proof, key rotation or durable pin
storage is established. Exit: 0 verified/help; 2 usage; 5 I/O; 8 verification.";

struct Request {
    anchor: super::Request,
    baseline: PathBuf,
    records: Vec<PathBuf>,
    range: Option<(PathBuf, ScopeClaim)>,
}

fn interval(value: &OsString) -> Result<(i32, i32), Failure> {
    let value = value.to_str().ok_or_else(|| Failure::usage("--expect-days must be ASCII"))?;
    let (first, last) = value.split_once(':')
        .ok_or_else(|| Failure::usage("--expect-days requires FIRST:LAST"))?;
    let day = |text: &str| {
        let digits = text.strip_prefix('-').unwrap_or(text);
        if text.len() > 11 || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Failure::usage("civil days must be signed decimal i32 values"));
        }
        text.parse::<i32>().map_err(|_| Failure::usage("civil day exceeds i32"))
    };
    let pair = (day(first)?, day(last)?);
    if pair.0 > pair.1 { return Err(Failure::usage("civil-day interval is reversed")); }
    Ok(pair)
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let mut anchor = vec![OsString::from("witness")];
    let (mut baseline, mut scope, mut account, mut days) = (None, None, None, None);
    let mut records = Vec::new();
    let mut at = 1;
    while let Some(argument) = args.get(at) {
        if argument == "--json" {
            anchor.push(argument.clone());
            at += 1;
            continue;
        }
        let name = argument.to_str().ok_or_else(|| Failure::usage("unknown index option"))?;
        let value = args.get(at + 1).ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(Failure::usage(format!("{name} requires a value; use ./ for paths beginning with --")));
        }
        if name == "--delta-record" {
            if records.len() == MAX_PRODUCTION_RECORDS {
                return Err(Failure::usage("at most 4096 delta records are permitted"));
            }
            records.push(PathBuf::from(value));
        } else {
            let slot = match name {
                "--baseline-prefix" => Some(&mut baseline),
                "--scope-proof" => Some(&mut scope),
                "--expect-account" => Some(&mut account),
                "--expect-days" => Some(&mut days),
                "--checkpoint" | "--previous" | "--expect-previous-body" | "--consistency"
                    | "--expect-book" | "--expect-branch" | "--expect-policy"
                    | "--publisher-key" | "--witness-key" | "--quorum" => None,
                _ => return Err(Failure::usage("unknown option; run fa-verify witness index --help")),
            };
            if let Some(slot) = slot {
                if slot.replace(value).is_some() {
                    return Err(Failure::usage(format!("{name} may be supplied only once")));
                }
            } else {
                anchor.extend([argument.clone(), value.clone()]);
            }
        }
        at += 2;
    }
    let range = match (scope, account, days) {
        (None, None, None) => None,
        (Some(path), Some(account), Some(days)) => {
            let account = u128::from_be_bytes(super::fixed::<16>(account, "--expect-account")?);
            let (from, to) = interval(days)?;
            Some((PathBuf::from(path), ScopeClaim { account, from, to }))
        }
        _ => return Err(Failure::usage("--scope-proof, --expect-account and --expect-days are required together")),
    };
    let baseline = PathBuf::from(super::required(baseline, "--baseline-prefix")?);
    let anchor = super::parse(&anchor)?;
    if anchor.advance.is_none() {
        return Err(Failure::usage("index advancement requires --previous, --expect-previous-body and --consistency"));
    }
    Ok(Request { anchor, baseline, records, range })
}

fn read(path: &Path, bound: usize, remaining: &mut usize) -> Result<Vec<u8>, Failure> {
    let bytes = read_bounded(path, bound.min(*remaining))?;
    *remaining -= bytes.len();
    Ok(bytes)
}

fn verify(args: &[OsString], json: bool) -> Result<String, Failure> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok(HELP.into());
    }
    let request = parse(args)?;
    let advance = request.anchor.advance.as_ref()
        .ok_or_else(|| Failure::usage("missing retained checkpoint options"))?;
    let mut remaining = MAX_PRODUCTION_BYTES;
    let bytes = read(&advance.previous, MAX_WITNESSED_CHECKPOINT_BYTES, &mut remaining)?;
    let previous = verify_witnessed_checkpoint(&bytes, &request.anchor.policy)
        .map_err(|e| Failure::verification(e.to_string()))?;
    if previous.signed_checkpoint().body_digest != advance.expected_body {
        return Err(Failure::verification("previous checkpoint does not match the independently retained body digest"));
    }
    drop(bytes);
    // An authentic previous pin and complete baseline are required before any
    // candidate/delta is observed. Do not learn a baseline from a candidate.
    let bytes = read(&request.baseline, MAX_PRODUCTION_BYTES, &mut remaining)?;
    let baseline = IncrementalPayloadIndex::verify(&bytes, &previous)
        .map_err(|e| Failure::verification(e.to_string()))?;
    drop(bytes);
    let candidate = read(&request.anchor.path, MAX_WITNESSED_CHECKPOINT_BYTES, &mut remaining)?;
    let consistency = read(&advance.proof, MAX_WITNESS_CONSISTENCY_BYTES, &mut remaining)?;
    let mut records = Vec::new();
    records.try_reserve_exact(request.records.len())
        .map_err(|_| Failure::verification("delta allocation failed"))?;
    for path in &request.records {
        records.push(read(path, MAX_PRODUCTION_BYTES, &mut remaining)?);
    }
    let slices: Vec<_> = records.iter().map(Vec::as_slice).collect();
    let current = baseline.advance(&candidate, &consistency, &slices)
        .map_err(|e| Failure::verification(e.to_string()))?;
    drop(slices);
    drop(records);
    drop(candidate);
    drop(consistency);
    let range = request.range.as_ref().map(|(path, claim)| {
        let bytes = read(path, MAX_PRODUCTION_BYTES, &mut remaining)?;
        verify_scope_with_payload_index(&bytes, current.checkpoint().signed_checkpoint(), claim, current.index())
            .map_err(|e| Failure::verification(e.to_string()))
    }).transpose()?;
    let text = render(&current, &previous, range.as_ref(), MAX_PRODUCTION_BYTES - remaining, json);
    if text.len() > MAX_PRODUCTION_BYTES {
        return Err(Failure::verification("index report exceeds 64 MiB"));
    }
    Ok(text)
}

pub(super) fn run(args: &[OsString]) -> Output {
    let json = args.iter().any(|arg| arg == "--json");
    match verify(args, json) {
        Ok(report) => Output { exit: 0, stdout: format!("{report}\n"), stderr: String::new() },
        Err(error) => Output {
            exit: i32::from(error.exit),
            stdout: if json { format!("{}\n", error.json()) } else { String::new() },
            stderr: format!("fa-verify: {}\n", error.message),
        },
    }
}

fn render(
    current: &IncrementalPayloadIndex,
    previous: &fa_verify::checkpoint::witness::WitnessedCheckpoint,
    range: Option<&ScopeReport>,
    input_bytes: usize,
    json: bool,
) -> String {
    let pin = current.checkpoint();
    let signed = pin.signed_checkpoint();
    let cp = &signed.checkpoint;
    let old = previous.signed_checkpoint();
    let appended = cp.leaf_count - old.checkpoint.leaf_count;
    let continuity = if cp.through_seq == old.checkpoint.through_seq { "unchanged" } else { "advanced" };
    if !json {
        let query = range.map_or_else(|| "No account-range query was requested.".into(), |r| format!(
            "Account {:032x}, days {} through {}: {} complete matching leaves (scope: {}).",
            r.account, r.from, r.to, r.leaves.len(), r.scope,
        ));
        return format!(
            "Verified incremental scope index: {continuity}, {appended} appended records, {} total tuples.\nCheckpoint body {} at sequence {}; index root {}.\nPublisher and {} witnesses verified ({} required). Recorded boundary verified.\n{query}\nWhole-baseline and suffix disclosure grants no authority. Global freshness, economic truth, key rotation and durable pin storage were not checked. No pin or payload bytes were written.",
            current.index().tuple_count(), hex(&signed.body_digest), cp.through_seq,
            hex(current.index().root()), pin.witnesses().len(), pin.required_witnesses(),
        );
    }
    object([
        ("event", quote("proof_verified")),
        ("proof_kind", quote("witnessed_index_advance")),
        ("verified", "true".into()),
        ("checkpoint", object([
            ("book_id", quote(&hex(&cp.book_id))), ("branch_id", quote(&hex(&cp.branch_id))),
            ("through_seq", quote(&cp.through_seq.to_string())),
            ("leaf_count", quote(&cp.leaf_count.to_string())),
            ("body_digest", quote(&hex(&signed.body_digest))),
            ("artifact_oid", quote(&hex(&signed.oid))), ("root", quote(&hex(&cp.root))),
        ])),
        ("previous_pin", object([
            ("body_digest", quote(&hex(&old.body_digest))),
            ("through_seq", quote(&old.checkpoint.through_seq.to_string())),
        ])),
        ("continuity", quote(continuity)),
        ("continuity_scope", quote("consistency")),
        ("recorded_boundary", quote("verified")),
        ("scope_index_derivation", quote("payload_recomputed")),
        ("index_root", quote(&hex(current.index().root()))),
        ("tuple_count", current.index().tuple_count().to_string()),
        ("appended_records", quote(&appended.to_string())),
        ("input_bytes", quote(&input_bytes.to_string())),
        ("policy_oid", signed.witness_policy_oid.map_or_else(|| "null".into(), |id| quote(&hex(&id)))),
        ("not_judged_signers", array(signed.not_judged.iter().map(|id| quote(&hex(id))))),
        ("required_witnesses", pin.required_witnesses().to_string()),
        ("witnesses", array(pin.witnesses().iter().map(|id| quote(&hex(id))))),
        ("range", range.map_or_else(|| "null".into(), |r| object([
            ("scope", quote(r.scope)), ("account", quote(&format!("{:032x}", r.account))),
            ("from", quote(&r.from.to_string())), ("to", quote(&r.to.to_string())),
            ("leaves", array(r.leaves.iter().map(|(i, envelope)| object([
                ("leaf_index", quote(&i.to_string())),
                ("record_digest", quote(&hex(&envelope.record_digest))),
                ("recorded_at", quote(&envelope.commit_seq.to_string())),
            ])))),
        ]))),
        ("pin_written", "false".into()),
        ("not_checked", array([
            "global_freshness", "authorization", "private_disclosure", "accounting_truth",
            "policy_registration", "key_rotation", "key_validity_intervals",
            "organizational_independence", "witness_authorization", "durable_pin_storage",
        ].map(quote))),
        ("v", "1".into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_are_exact_signed_i32_values_with_no_inference() {
        assert_eq!(interval(&"-2147483648:2147483647".into()).ok(), Some((i32::MIN, i32::MAX)));
        for text in ["all", "0", "1:0", "+1:2", "0:2147483648", "-2147483649:0", "0: 1", "０:1"] {
            assert!(interval(&text.into()).is_err(), "{text}");
        }
    }
}
