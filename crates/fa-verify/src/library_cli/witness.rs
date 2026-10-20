//! Offline recipient-owned checkpoint quorums. No trust setting is learned
//! from the signed file, and no fallback to the any-trusted-signer command.

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::checkpoint::signer_key_id;
use fa_verify::checkpoint::witness::{
    MAX_WITNESSED_CHECKPOINT_BYTES, RecipientWitnessPolicy, WitnessedCheckpoint,
    verify_witnessed_checkpoint,
};
use fa_verify::cli::Output;

use crate::{Failure, array, hex, object, quote, read_bounded};

pub(super) const HELP: &str = "Recipient-owned checkpoint witness quorum:
  fa-verify witness --checkpoint SIGNED_FILE --expect-book HEX32 \\
    --expect-branch HEX32 --expect-policy HEX64 --publisher-key HEX64 \\
    --witness-key HEX64 [--witness-key HEX64 ...] --quorum N [--json]

Obtain ALL expected identifiers, keys and the quorum independently. HEX32
and HEX64 mean exactly 32 and 64 ASCII hex digits, respectively. The input
is raw TransparencyCheckpoint v1 bytes, not hex text or an unsigned anchor.
Require the publisher AND N distinct configured witness keys (1..63).
Duplicate keys, publisher/witness overlap and impossible quorums refuse;
unknown signers never count. EVERY supplied signature by a configured key
must verify, even after enough witnesses passed. The policy ID is bound,
not fetched or authenticated as a policy document. Keys need not be sorted.

All syntax and policy checks precede file I/O. File size is bounded by the
signed-checkpoint decoder's maximum frame, including unknown signatures.
Non-UTF-8 file paths are supported; identifiers and keys must be ASCII hex.
Reports contain only public checkpoint metadata and signer IDs. This mode
checks signatures and the recipient quorum, NOT continuity, global freshness,
organizational independence, witness authorization, key validity intervals,
policy registration/rotation, index derivation or accounting truth.
No book, keys with signing authority, network or persistent writes are used.
Exit codes: 0 verified/help; 2 usage/policy; 5 file/output I/O; 8 verification failed.";

struct Request {
    path: PathBuf,
    policy: RecipientWitnessPolicy,
    publisher_id: [u8; 32],
    witness_count: usize,
}

fn required<'a>(value: Option<&'a OsString>, name: &str) -> Result<&'a OsString, Failure> {
    value.ok_or_else(|| Failure::usage(format!("{name} is required independently of the checkpoint")))
}

fn fixed<const N: usize>(value: &OsString, name: &str) -> Result<[u8; N], Failure> {
    let text = value.to_str().ok_or_else(|| Failure::usage(format!("{name} must be ASCII hex")))?;
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::usage(format!("{name} requires exactly {} ASCII hex digits", N * 2)));
    }
    let mut result = [0; N];
    for (i, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| Failure::usage(format!("invalid {name}")))?;
    }
    Ok(result)
}

fn quorum(value: &OsString) -> Result<usize, Failure> {
    let text = value.to_str().ok_or_else(|| Failure::usage("--quorum must be ASCII decimal"))?;
    if text.is_empty() || text.len() > 2 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::usage("--quorum requires a decimal integer from 1 through 63"));
    }
    text.parse().map_err(|_| Failure::usage("invalid --quorum"))
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let (mut path, mut book, mut branch, mut policy, mut publisher, mut threshold) =
        (None, None, None, None, None, None);
    let mut witnesses = Vec::new();
    let mut json = false;
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if argument == "--json" {
            if json { return Err(Failure::usage("--json may be supplied only once")); }
            json = true;
            index += 1;
            continue;
        }
        let name = argument.to_str().ok_or_else(|| Failure::usage("unknown witness option"))?;
        if !matches!(name, "--checkpoint" | "--expect-book" | "--expect-branch"
            | "--expect-policy" | "--publisher-key" | "--witness-key" | "--quorum")
        {
            return Err(Failure::usage("unknown witness option; run fa-verify witness --help"));
        }
        let value = args.get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(Failure::usage(format!("{name} requires a value; use ./ for paths beginning with --")));
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
                _ => &mut threshold,
            };
            if slot.replace(value).is_some() {
                return Err(Failure::usage(format!("{name} may be supplied only once")));
            }
        }
        index += 2;
    }
    let path = PathBuf::from(required(path, "--checkpoint")?);
    let book = fixed::<16>(required(book, "--expect-book")?, "--expect-book")?;
    let branch = fixed::<16>(required(branch, "--expect-branch")?, "--expect-branch")?;
    let policy_id = fixed::<32>(required(policy, "--expect-policy")?, "--expect-policy")?;
    let publisher = fixed::<32>(required(publisher, "--publisher-key")?, "--publisher-key")?;
    let threshold = quorum(required(threshold, "--quorum")?)?;
    let policy = RecipientWitnessPolicy::new(book, branch, policy_id, publisher, &witnesses, threshold)
        .map_err(|error| Failure::usage(error.to_string()))?;
    Ok(Request { path, policy, publisher_id: signer_key_id(&publisher), witness_count: witnesses.len() })
}

fn verify(args: &[OsString], json: bool) -> Result<String, Failure> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok(HELP.into());
    }
    let request = parse(args)?;
    let bytes = read_bounded(&request.path, MAX_WITNESSED_CHECKPOINT_BYTES)?;
    let verified = verify_witnessed_checkpoint(&bytes, &request.policy)
        .map_err(|error| Failure::verification(error.to_string()))?;
    Ok(render(&verified, &request, json))
}

pub(super) fn run(args: &[OsString]) -> Output {
    let json = args.iter().any(|argument| argument == "--json");
    match verify(args, json) {
        Ok(report) => Output { exit: 0, stdout: format!("{report}\n"), stderr: String::new() },
        Err(error) => Output {
            exit: i32::from(error.exit),
            stdout: if json { format!("{}\n", error.json()) } else { String::new() },
            stderr: format!("fa-verify: {}\n", error.message),
        },
    }
}

fn render(report: &WitnessedCheckpoint, request: &Request, json: bool) -> String {
    let signed = report.signed_checkpoint();
    let checkpoint = &signed.checkpoint;
    if !json {
        return format!(
            "Verified checkpoint signatures: publisher and {} distinct witnesses ({} required of {} configured).\nBook {} branch {} at sequence {}, {} leaves.\nSigned body digest: {}.\nArtifact digest: {}.\n{} unknown signatures were not judged. Continuity and freshness were not checked.\nPolicy ID binding does not verify policy registration, witness authority, key validity/rotation, organizational independence, index construction or accounting truth. No pin was written.",
            report.witnesses().len(), report.required_witnesses(), request.witness_count,
            hex(&checkpoint.book_id), hex(&checkpoint.branch_id), checkpoint.through_seq,
            checkpoint.leaf_count, hex(&signed.body_digest), hex(&signed.oid), signed.not_judged.len(),
        );
    }
    object([
        ("event", quote("proof_verified")),
        ("proof_kind", quote("witnessed_checkpoint")),
        ("anchor", object([
            ("source", quote("recipient_owned_witness_policy")),
            ("publisher_key_id", quote(&hex(&request.publisher_id))),
            ("configured_witnesses", request.witness_count.to_string()),
            ("required_witnesses", report.required_witnesses().to_string()),
            ("policy_oid", signed.witness_policy_oid.map_or_else(|| "null".into(), |id| quote(&hex(&id)))),
        ])),
        ("checkpoint", object([
            ("book_id", quote(&hex(&checkpoint.book_id))),
            ("branch_id", quote(&hex(&checkpoint.branch_id))),
            ("through_seq", quote(&checkpoint.through_seq.to_string())),
            ("leaf_count", quote(&checkpoint.leaf_count.to_string())),
            ("root", quote(&hex(&checkpoint.root))),
            ("body_digest", quote(&hex(&signed.body_digest))),
            ("artifact_oid", quote(&hex(&signed.oid))),
        ])),
        ("checks", array([
            "expected_book_and_branch", "expected_policy_id", "publisher_signature",
            "all_configured_signatures", "distinct_witness_quorum",
        ].map(|name| object([("name", quote(name)), ("status", quote("pass"))])))),
        ("witnesses", array(report.witnesses().iter().map(|id| quote(&hex(id))))),
        ("not_judged_signers", array(signed.not_judged.iter().map(|id| quote(&hex(id))))),
        ("continuity", quote("not_checked")),
        ("pin_written", "false".into()),
        ("not_checked", array([
            "global_freshness", "policy_registration", "witness_authorization",
            "key_validity_intervals", "key_rotation", "organizational_independence",
            "index_derivation", "accounting_truth", "durable_pin_storage",
        ].map(quote))),
        ("v", "1".into()),
        ("verified", "true".into()),
    ])
}
