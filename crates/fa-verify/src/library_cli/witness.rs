//! Offline recipient-owned checkpoint quorums. No trust setting is learned
//! from the signed file, and no fallback to the any-trusted-signer command.

mod bundle;
mod recorded;

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::checkpoint::signer_key_id;
use fa_verify::checkpoint::witness::{
    AdvanceStatus, MAX_WITNESS_CONSISTENCY_BYTES, MAX_WITNESSED_CHECKPOINT_BYTES,
    RecipientWitnessPolicy, WitnessedCheckpoint, verify_checkpoint_advance,
    verify_witnessed_checkpoint,
};
use fa_verify::cli::Output;

use crate::{Failure, array, hex, object, quote, read_bounded};

pub(super) const HELP: &str = "Recipient-owned checkpoint witness quorum:
  fa-verify witness --checkpoint SIGNED_FILE --expect-book HEX32 \\
    --expect-branch HEX32 --expect-policy HEX64 --publisher-key HEX64 \\
    --witness-key HEX64 [--witness-key HEX64 ...] --quorum N [--json]

To bind a production to this trust decision: fa-verify witness bundle --help

Obtain ALL expected identifiers, keys and the quorum independently. HEX32
and HEX64 mean exactly 32 and 64 ASCII hex digits, respectively. The input
is raw TransparencyCheckpoint v1 bytes, not hex text or an unsigned anchor.
Require the publisher AND N distinct configured witness keys (1..63).
Duplicate keys, publisher/witness overlap and impossible quorums refuse;
unknown signers never count. EVERY supplied signature by a configured key
must verify, even after enough witnesses passed. The policy ID is bound,
not fetched or authenticated as a policy document. Keys need not be sorted.

To require continuity from an independently retained pin, add ALL THREE:
  --previous PREVIOUS_SIGNED_FILE --expect-previous-body HEX64 --consistency PROOF
The expected BODY digest must be retained independently, not copied from the
supplied previous file. Both signed checkpoints must satisfy the SAME explicit
recipient policy. An exact append-only proof is mandatory, even for a no-op.
The command refuses rollback, forks and changed signed bodies at one sequence.
Different sufficient signature subsets over the SAME body remain unchanged.
No new policy, key rotation, global freshness or record/index semantics are
inferred from a valid extension. The report's body_digest is the next pin;
storing it securely and retaining the recipient policy remain YOUR responsibility.
The command never overwrites either input or installs a new pin.

To ALSO preserve the retained recorded-time boundary, add --recorded-prefix FILE.
This option REQUIRES all three continuity options. FILE must be a native v2
payload-complete prefix or v3 balance export for the candidate checkpoint.
Every payload must verify, and exactly the retained leaf count must fall at
or before its retained sequence. New records at old recorded sequences fail;
legitimate later-recorded entries with earlier EFFECTIVE dates remain valid.
Envelope-only or missing/corrupt witnesses refuse without a weaker fallback.
The witness discloses the ENTIRE prefix and grants no disclosure authority.
Previous/candidate checkpoints, consistency proof and recorded prefix share
one 64 MiB budget; in bundle mode this also includes bundle, receipt and any
separate index witness. Repeated inputs count each time. No payload is printed.
Without --recorded-prefix, continuity proves tree extension only and the
recorded boundary is explicitly not_checked. Index correctness remains separate.

All syntax and policy checks precede file I/O. File size is bounded by the
signed-checkpoint decoder's maximum frame, including unknown signatures.
Non-UTF-8 file paths are supported; identifiers and keys must be ASCII hex.
Reports contain only public checkpoint metadata and signer IDs. This mode
checks signatures and the recipient quorum; continuity needs the three pin
options above. Neither mode establishes global freshness,
organizational independence, witness authorization, key validity intervals,
policy registration/rotation, index derivation or accounting truth.
No book, keys with signing authority, network or persistent writes are used.
Exit codes: 0 verified/help; 2 usage/policy; 5 file/output I/O; 8 verification failed.";

struct Request {
    path: PathBuf,
    policy: RecipientWitnessPolicy,
    publisher_id: [u8; 32],
    witness_count: usize,
    advance: Option<AdvanceRequest>,
}

struct AdvanceRequest {
    previous: PathBuf,
    expected_body: [u8; 32],
    proof: PathBuf,
    recorded_prefix: Option<PathBuf>,
}

struct Continuity {
    status: AdvanceStatus,
    previous_body: [u8; 32],
    previous_seq: u64,
    recorded: Option<recorded::Facts>,
}

impl Continuity {
    fn name(&self) -> &'static str {
        match self.status {
            AdvanceStatus::Advanced => "advanced",
            AdvanceStatus::Unchanged => "unchanged",
        }
    }
}

fn required<'a>(value: Option<&'a OsString>, name: &str) -> Result<&'a OsString, Failure> {
    value.ok_or_else(|| {
        Failure::usage(format!(
            "{name} is required independently of the checkpoint"
        ))
    })
}

fn fixed<const N: usize>(value: &OsString, name: &str) -> Result<[u8; N], Failure> {
    let text = value
        .to_str()
        .ok_or_else(|| Failure::usage(format!("{name} must be ASCII hex")))?;
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::usage(format!(
            "{name} requires exactly {} ASCII hex digits",
            N * 2
        )));
    }
    let mut result = [0; N];
    for (i, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| Failure::usage(format!("invalid {name}")))?;
    }
    Ok(result)
}

fn quorum(value: &OsString) -> Result<usize, Failure> {
    let text = value
        .to_str()
        .ok_or_else(|| Failure::usage("--quorum must be ASCII decimal"))?;
    if text.is_empty() || text.len() > 2 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::usage(
            "--quorum requires a decimal integer from 1 through 63",
        ));
    }
    text.parse().map_err(|_| Failure::usage("invalid --quorum"))
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let (mut path, mut book, mut branch, mut policy, mut publisher, mut threshold) =
        (None, None, None, None, None, None);
    let (mut previous, mut previous_body, mut consistency) = (None, None, None);
    let mut recorded_prefix = None;
    let mut witnesses = Vec::new();
    let mut json = false;
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if argument == "--json" {
            if json {
                return Err(Failure::usage("--json may be supplied only once"));
            }
            json = true;
            index += 1;
            continue;
        }
        let name = argument
            .to_str()
            .ok_or_else(|| Failure::usage("unknown witness option"))?;
        if !matches!(
            name,
            "--checkpoint"
                | "--expect-book"
                | "--expect-branch"
                | "--expect-policy"
                | "--publisher-key"
                | "--witness-key"
                | "--quorum"
                | "--previous"
                | "--expect-previous-body"
                | "--consistency"
                | "--recorded-prefix"
        ) {
            return Err(Failure::usage(
                "unknown witness option; run fa-verify witness --help",
            ));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(Failure::usage(format!(
                "{name} requires a value; use ./ for paths beginning with --"
            )));
        }
        if name == "--witness-key" {
            if witnesses.len() == 63 {
                return Err(Failure::usage("at most 63 witness keys are permitted"));
            }
            witnesses.push(fixed::<32>(value, name)?);
        } else {
            let slot = match name {
                "--checkpoint" => &mut path,
                "--expect-book" => &mut book,
                "--expect-branch" => &mut branch,
                "--expect-policy" => &mut policy,
                "--publisher-key" => &mut publisher,
                "--previous" => &mut previous,
                "--expect-previous-body" => &mut previous_body,
                "--consistency" => &mut consistency,
                "--recorded-prefix" => &mut recorded_prefix,
                _ => &mut threshold,
            };
            if slot.replace(value).is_some() {
                return Err(Failure::usage(format!("{name} may be supplied only once")));
            }
        }
        index += 2;
    }
    let advance = match (previous, previous_body, consistency, recorded_prefix) {
        (None, None, None, None) => None,
        (Some(previous), Some(body), Some(proof), recorded_prefix) => Some(AdvanceRequest {
            previous: PathBuf::from(previous),
            expected_body: fixed::<32>(body, "--expect-previous-body")?,
            proof: PathBuf::from(proof),
            recorded_prefix: recorded_prefix.map(PathBuf::from),
        }),
        _ => {
            return Err(Failure::usage(
                "--previous, --expect-previous-body and --consistency are required together; --recorded-prefix requires all three",
            ));
        }
    };
    let path = PathBuf::from(required(path, "--checkpoint")?);
    let book = fixed::<16>(required(book, "--expect-book")?, "--expect-book")?;
    let branch = fixed::<16>(required(branch, "--expect-branch")?, "--expect-branch")?;
    let policy_id = fixed::<32>(required(policy, "--expect-policy")?, "--expect-policy")?;
    let publisher = fixed::<32>(required(publisher, "--publisher-key")?, "--publisher-key")?;
    let threshold = quorum(required(threshold, "--quorum")?)?;
    let policy =
        RecipientWitnessPolicy::new(book, branch, policy_id, publisher, &witnesses, threshold)
            .map_err(|error| Failure::usage(error.to_string()))?;
    Ok(Request {
        path,
        policy,
        publisher_id: signer_key_id(&publisher),
        witness_count: witnesses.len(),
        advance,
    })
}

fn verify(args: &[OsString], json: bool) -> Result<String, Failure> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok(HELP.into());
    }
    let request = parse(args)?;
    let (verified, continuity) = authenticate(&request)?;
    Ok(render(&verified, &request, continuity.as_ref(), json))
}

// Shared by checkpoint-only and bundle workflows: a substituted old file must
// be rejected before either workflow observes any candidate accounting artifact.
fn authenticate(request: &Request) -> Result<(WitnessedCheckpoint, Option<Continuity>), Failure> {
    if let Some(advance) = &request.advance {
        let bytes = read_bounded(&advance.previous, MAX_WITNESSED_CHECKPOINT_BYTES)?;
        let previous = verify_witnessed_checkpoint(&bytes, &request.policy)
            .map_err(|error| Failure::verification(error.to_string()))?;
        if previous.signed_checkpoint().body_digest != advance.expected_body {
            return Err(Failure::verification(
                "previous checkpoint does not match the independently retained body digest",
            ));
        }
        let previous_bytes = bytes.len();
        drop(bytes);
        // Bind the previous file BEFORE observing the candidate or proof.
        // Neither a valid older artifact nor a different signed history may
        // replace the recipient's retained baseline by changing a file path.
        let candidate = read_bounded(&request.path, MAX_WITNESSED_CHECKPOINT_BYTES)?;
        let proof = read_bounded(&advance.proof, MAX_WITNESS_CONSISTENCY_BYTES)?;
        if let Some(path) = &advance.recorded_prefix {
            let (verified, facts) = recorded::authenticate(
                &previous, &candidate, &proof, path, previous_bytes,
            )?;
            let continuity = Continuity {
                status: verified.status(),
                previous_body: advance.expected_body,
                previous_seq: previous.signed_checkpoint().checkpoint.through_seq,
                recorded: Some(facts),
            };
            return Ok((verified.into_checkpoint(), Some(continuity)));
        }
        let verified = verify_checkpoint_advance(&previous, &candidate, &proof)
            .map_err(|error| Failure::verification(error.to_string()))?;
        let continuity = Continuity {
            status: verified.status(),
            previous_body: advance.expected_body,
            previous_seq: previous.signed_checkpoint().checkpoint.through_seq,
            recorded: None,
        };
        return Ok((verified.into_checkpoint(), Some(continuity)));
    }
    let bytes = read_bounded(&request.path, MAX_WITNESSED_CHECKPOINT_BYTES)?;
    let verified = verify_witnessed_checkpoint(&bytes, &request.policy)
        .map_err(|error| Failure::verification(error.to_string()))?;
    Ok((verified, None))
}

pub(super) fn run(args: &[OsString]) -> Output {
    if args.get(1).is_some_and(|arg| arg == "bundle") {
        return bundle::run(&args[1..]);
    }
    let json = args.iter().any(|argument| argument == "--json");
    match verify(args, json) {
        Ok(report) => Output {
            exit: 0,
            stdout: format!("{report}\n"),
            stderr: String::new(),
        },
        Err(error) => Output {
            exit: i32::from(error.exit),
            stdout: if json {
                format!("{}\n", error.json())
            } else {
                String::new()
            },
            stderr: format!("fa-verify: {}\n", error.message),
        },
    }
}

fn render(
    report: &WitnessedCheckpoint,
    request: &Request,
    continuity: Option<&Continuity>,
    json: bool,
) -> String {
    let signed = report.signed_checkpoint();
    let checkpoint = &signed.checkpoint;
    if !json {
        let mut history = continuity.map_or_else(
            || "Continuity and freshness were not checked.".into(),
            |pin| format!(
                "Continuity: {} (scope: consistency) from body {} at sequence {}. Global freshness was not checked.",
                pin.name(), hex(&pin.previous_body), pin.previous_seq,
            ),
        );
        history.push(' ');
        history.push_str(&recorded::human(continuity.and_then(|pin| pin.recorded.as_ref())));
        return format!(
            "Verified checkpoint signatures: publisher and {} distinct witnesses ({} required of {} configured).\nBook {} branch {} at sequence {}, {} leaves.\nSigned body digest: {}.\nArtifact digest: {}.\n{} unknown signatures were not judged. {history}\nPolicy ID binding does not verify policy registration, witness authority, key validity/rotation, organizational independence, index construction or accounting truth. No pin was written.",
            report.witnesses().len(),
            report.required_witnesses(),
            request.witness_count,
            hex(&checkpoint.book_id),
            hex(&checkpoint.branch_id),
            checkpoint.through_seq,
            checkpoint.leaf_count,
            hex(&signed.body_digest),
            hex(&signed.oid),
            signed.not_judged.len(),
        );
    }
    let mut checks = vec![
        "expected_book_and_branch",
        "expected_policy_id",
        "publisher_signature",
        "all_configured_signatures",
        "distinct_witness_quorum",
    ];
    if continuity.is_some() {
        checks.extend([
            "previous_body_matches_retained_pin",
            "previous_publisher_and_quorum",
            "same_recipient_policy",
            "append_only_consistency",
            "same_sequence_body_identity",
        ]);
    }
    if continuity.is_some_and(|pin| pin.recorded.is_some()) {
        checks.extend(["complete_candidate_payloads", "retained_recorded_boundary"]);
    }
    object([
        ("event", quote("proof_verified")),
        ("proof_kind", quote("witnessed_checkpoint")),
        (
            "anchor",
            object([
                ("source", quote("recipient_owned_witness_policy")),
                ("publisher_key_id", quote(&hex(&request.publisher_id))),
                ("configured_witnesses", request.witness_count.to_string()),
                (
                    "required_witnesses",
                    report.required_witnesses().to_string(),
                ),
                (
                    "policy_oid",
                    signed
                        .witness_policy_oid
                        .map_or_else(|| "null".into(), |id| quote(&hex(&id))),
                ),
            ]),
        ),
        (
            "checkpoint",
            object([
                ("book_id", quote(&hex(&checkpoint.book_id))),
                ("branch_id", quote(&hex(&checkpoint.branch_id))),
                ("through_seq", quote(&checkpoint.through_seq.to_string())),
                ("leaf_count", quote(&checkpoint.leaf_count.to_string())),
                ("root", quote(&hex(&checkpoint.root))),
                ("body_digest", quote(&hex(&signed.body_digest))),
                ("artifact_oid", quote(&hex(&signed.oid))),
            ]),
        ),
        (
            "checks",
            array(
                checks
                    .into_iter()
                    .map(|name| object([("name", quote(name)), ("status", quote("pass"))])),
            ),
        ),
        (
            "witnesses",
            array(report.witnesses().iter().map(|id| quote(&hex(id)))),
        ),
        (
            "not_judged_signers",
            array(signed.not_judged.iter().map(|id| quote(&hex(id)))),
        ),
        (
            "continuity",
            quote(continuity.map_or("not_checked", Continuity::name)),
        ),
        (
            "continuity_scope",
            continuity.map_or_else(|| "null".into(), |_| quote("consistency")),
        ),
        (
            "previous_pin",
            continuity.map_or_else(
                || "null".into(),
                |pin| {
                    object([
                        ("body_digest", quote(&hex(&pin.previous_body))),
                        ("through_seq", quote(&pin.previous_seq.to_string())),
                    ])
                },
            ),
        ),
        (
            "recorded_boundary",
            recorded::json(continuity.and_then(|pin| pin.recorded.as_ref())),
        ),
        ("pin_written", "false".into()),
        (
            "not_checked",
            array(
                [
                    "global_freshness",
                    "policy_registration",
                    "witness_authorization",
                    "key_validity_intervals",
                    "key_rotation",
                    "organizational_independence",
                    "index_derivation",
                    "accounting_truth",
                    "durable_pin_storage",
                ]
                .map(quote),
            ),
        ),
        ("v", "1".into()),
        ("verified", "true".into()),
    ])
}
