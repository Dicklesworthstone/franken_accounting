//! One recipient request binds quorum/continuity, bundle scope, disclosure and receipt.

mod balances;

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::checkpoint::witness::WitnessedCheckpoint;
use fa_verify::checkpoint::witness::bundle::{
    BundleExpectation, MAX_REQUESTED_BUNDLE_LEAVES, MAX_WITNESSED_BUNDLE_BYTES,
    MAX_WITNESSED_RECEIPT_BYTES, verify_witnessed_bundle_for,
};
use fa_verify::checkpoint::witness::bundle::balances::verify_witnessed_bundle_balances_for;
use fa_verify::cli::Output;
use fa_verify::{BundleReport, BundleScope, Grade, ScopeClaim};

use crate::{Failure, array, hex, object, quote, read_bounded};

const HELP: &str = "Recipient-bound witnessed evidence bundle:
  fa-verify witness bundle --bundle FILE --checkpoint SIGNED_FILE \\
    --expect-book HEX32 --expect-branch HEX32 --expect-policy HEX64 \\
    --publisher-key HEX64 --witness-key HEX64 [--witness-key HEX64 ...] --quorum N \\
    --expect-scope prefix|account|entries --expect-documents inline|commitments \\
    --expect-receipt publisher|optional [--receipt FILE] [--json]

Every trust setting and expectation must come from the recipient, not input.
Scope prefix means the entire pinned prefix; account additionally requires
--expect-account HEX32 --expect-days FIRST:LAST (inclusive signed i32 days).
Scope entries requires --expect-leaves I,J or the explicit empty list none.
Leaves are ascending unique decimal u64 indices, never sorted or inferred.
The account is a numeric u128 encoded as 32 hexadecimal digits, not a code.
Selectors for other scope kinds are refused before files are opened.

inline requires every cited document's full bytes; commitments permits omitted
bytes and does not claim they were checked. publisher requires a detached
receipt signed by the publisher; optional does not require one, but any supplied
receipt must verify. Witness keys NEVER gain receipt-signing authority.

All ordinary witness options are supported, including the all-or-none
--previous FILE --expect-previous-body HEX64 --consistency PROOF continuity
request. The previous body must match an independently retained pin before
later artifacts are opened. Without those options, continuity is NOT checked.
See fa-verify witness --help for checkpoint policy and continuity details.

The bundle must name the EXACT selected signed-checkpoint artifact, not just
a matching tree or body. Stripped or alternate signature sets require their
own independently verified anchor. Every bundle predicate retains its own
pass/fail/unrun grade; a matching quorum never repairs an incomplete balance.
Account completeness retains the signed-index (not recomputed) premise.
To demand exact stock cells, repeat --expect-balance ACCOUNT32:UNIT:DAY|none
or ACCOUNT32:UNIT:DAY|none:DEBITS:CREDITS for optional exact gross mantissas.
ACCOUNT32 is 32 hex digits; UNIT is decimal u32; DAY is signed decimal i32.
Amounts are nonnegative integer i128 mantissas, never decimal money or nets.
Cells are an EXACT set independent of proof order, with no duplicates or extras.
At most 4096 cells may be requested. The literal none means no stock cutoff,
not a wildcard; stock cutoffs are independent of the entry-scope day interval.
Use --expect-no-balances to require zero claims. It cannot be combined with
--expect-balance. With neither flag no specific balance set is requested.
Every balance must still satisfy its full recomputation obligations.

Input is canonical raw bytes, never hex text. Bundle plus receipt share a
64 MiB budget; a receipt is at most 4096 bytes. Paths may be non-UTF-8.
Output contains public metadata only. No files or pins are written. Global
freshness, custody, policy registration, key rotation, authorization, full
provenance and accounting truth are not established by this operation.
Exit codes: 0 all required checks passed/help; 2 usage; 5 I/O; 8 verification.";

struct Request {
    anchor: super::Request,
    bundle: PathBuf,
    receipt: Option<PathBuf>,
    expected: BundleExpectation,
    balances: Option<Vec<fa_verify::BalanceExpectation>>,
}

fn text<'a>(value: Option<&'a OsString>, name: &str) -> Result<&'a str, Failure> {
    super::required(value, name)?
        .to_str()
        .ok_or_else(|| Failure::usage(format!("{name} must be ASCII")))
}

fn day(value: &str) -> Result<i32, Failure> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if value.len() > 11 || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Failure::usage(
            "day bounds must be signed decimal i32 values",
        ));
    }
    value
        .parse()
        .map_err(|_| Failure::usage("day bound exceeds i32"))
}

fn leaves(value: &str) -> Result<Vec<u64>, Failure> {
    if value == "none" {
        return Ok(vec![]);
    }
    if value.is_empty() || value.len() > MAX_REQUESTED_BUNDLE_LEAVES * 21 {
        return Err(Failure::usage(
            "--expect-leaves requires a bounded list or none",
        ));
    }
    let mut result = Vec::new();
    for token in value.split(',') {
        if result.len() == MAX_REQUESTED_BUNDLE_LEAVES
            || token.is_empty()
            || token.len() > 20
            || !token.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Failure::usage("invalid or excessive requested leaf list"));
        }
        result.push(
            token
                .parse()
                .map_err(|_| Failure::usage("leaf index exceeds u64"))?,
        );
    }
    Ok(result)
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let mut anchor = vec![OsString::from("witness")];
    let (mut bundle, mut receipt, mut scope, mut documents, mut receipt_mode) =
        (None, None, None, None, None);
    let (mut account, mut days, mut indexes) = (None, None, None);
    let mut balance_args = balances::BalanceArgs::default();
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if let Some(consumed) = balance_args.consume(args, index)? {
            index += consumed;
            continue;
        }
        if argument == "--json" {
            anchor.push(argument.clone());
            index += 1;
            continue;
        }
        let name = argument
            .to_str()
            .ok_or_else(|| Failure::usage("unknown witnessed bundle option"))?;
        let value = args
            .get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(Failure::usage(format!(
                "{name} requires a value; use ./ for paths starting with --"
            )));
        }
        let slot = match name {
            "--bundle" => Some(&mut bundle),
            "--receipt" => Some(&mut receipt),
            "--expect-scope" => Some(&mut scope),
            "--expect-documents" => Some(&mut documents),
            "--expect-receipt" => Some(&mut receipt_mode),
            "--expect-account" => Some(&mut account),
            "--expect-days" => Some(&mut days),
            "--expect-leaves" => Some(&mut indexes),
            "--checkpoint"
            | "--expect-book"
            | "--expect-branch"
            | "--expect-policy"
            | "--publisher-key"
            | "--witness-key"
            | "--quorum"
            | "--previous"
            | "--expect-previous-body"
            | "--consistency" => None,
            _ => {
                return Err(Failure::usage(
                    "unknown option; run fa-verify witness bundle --help",
                ));
            }
        };
        if let Some(slot) = slot {
            if slot.replace(value).is_some() {
                return Err(Failure::usage(format!("{name} may be supplied only once")));
            }
        } else {
            anchor.extend([argument.clone(), value.clone()]);
        }
        index += 2;
    }
    let balances = balance_args.finish()?;
    let scope = match text(scope, "--expect-scope")? {
        "prefix" if account.is_none() && days.is_none() && indexes.is_none() => BundleScope::Prefix,
        "account" if indexes.is_none() => {
            let account = u128::from_be_bytes(super::fixed::<16>(
                super::required(account, "--expect-account")?,
                "--expect-account",
            )?);
            let interval = text(days, "--expect-days")?;
            let (first, last) = interval
                .split_once(':')
                .ok_or_else(|| Failure::usage("--expect-days requires FIRST:LAST"))?;
            BundleScope::Account(ScopeClaim {
                account,
                from: day(first)?,
                to: day(last)?,
            })
        }
        "entries" if account.is_none() && days.is_none() => {
            BundleScope::Entries(leaves(text(indexes, "--expect-leaves")?)?)
        }
        _ => {
            return Err(Failure::usage(
                "scope must be prefix/account/entries with exactly its own selectors",
            ));
        }
    };
    let inline_documents = match text(documents, "--expect-documents")? {
        "inline" => true,
        "commitments" => false,
        _ => {
            return Err(Failure::usage(
                "--expect-documents requires inline or commitments",
            ));
        }
    };
    let publisher_receipt = match text(receipt_mode, "--expect-receipt")? {
        "publisher" => true,
        "optional" => false,
        _ => {
            return Err(Failure::usage(
                "--expect-receipt requires publisher or optional",
            ));
        }
    };
    let expected = BundleExpectation {
        scope,
        inline_documents,
        publisher_receipt,
    };
    expected
        .validate()
        .map_err(|error| Failure::usage(error.to_string()))?;
    let bundle = PathBuf::from(super::required(bundle, "--bundle")?);
    // The shared parser admits keys and all continuity options before any I/O.
    let anchor = super::parse(&anchor)?;
    Ok(Request {
        anchor,
        bundle,
        receipt: receipt.map(PathBuf::from),
        expected,
        balances,
    })
}

fn verify(args: &[OsString], json: bool) -> Result<(String, bool), Failure> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok((HELP.into(), true));
    }
    let request = parse(args)?;
    let (pin, continuity) = super::authenticate(&request.anchor)?;
    let receipt = request
        .receipt
        .as_ref()
        .map(|path| read_bounded(path, MAX_WITNESSED_RECEIPT_BYTES))
        .transpose()?;
    let remaining = MAX_WITNESSED_BUNDLE_BYTES - receipt.as_ref().map_or(0, Vec::len);
    let bytes = read_bounded(&request.bundle, remaining)?;
    let report = match &request.balances {
        Some(expected) => verify_witnessed_bundle_balances_for(
            &bytes, &pin, &request.expected, expected, receipt.as_deref(),
        ),
        None => verify_witnessed_bundle_for(&bytes, &pin, &request.expected, receipt.as_deref()),
    }
    .map_err(|error| Failure::verification(error.to_string()))?;
    let passed = report.verified();
    let output = render(&report, &pin, &request, continuity.as_ref(), json);
    if output.len() > MAX_WITNESSED_BUNDLE_BYTES {
        return Err(Failure::verification(
            "witnessed bundle report exceeds 64 MiB",
        ));
    }
    Ok((output, passed))
}

pub(super) fn run(args: &[OsString]) -> Output {
    let json = args.iter().any(|arg| arg == "--json");
    match verify(args, json) {
        Ok((report, passed)) => Output {
            exit: if passed { 0 } else { 8 },
            stdout: format!("{report}\n"),
            stderr: if passed {
                String::new()
            } else {
                "fa-verify: bundle did not satisfy every required predicate\n".into()
            },
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

fn scope_json(scope: &BundleScope) -> String {
    match scope {
        BundleScope::Prefix => object([("kind", quote("prefix"))]),
        BundleScope::Account(claim) => object([
            ("kind", quote("account")),
            ("account", quote(&format!("{:032x}", claim.account))),
            ("from", quote(&claim.from.to_string())),
            ("to", quote(&claim.to.to_string())),
        ]),
        BundleScope::Entries(leaves) => object([
            ("kind", quote("entries")),
            (
                "leaves",
                array(leaves.iter().map(|i| quote(&i.to_string()))),
            ),
        ]),
    }
}

fn grade(grade: &Grade) -> (&'static str, Option<&str>) {
    match grade {
        Grade::Pass => ("pass", None),
        Grade::Fail(why) => ("fail", Some(why)),
        Grade::Unrun(why) => ("unrun", Some(why)),
    }
}

fn render(
    report: &BundleReport,
    pin: &WitnessedCheckpoint,
    request: &Request,
    continuity: Option<&super::Continuity>,
    json: bool,
) -> String {
    let signed = pin.signed_checkpoint();
    let cp = &signed.checkpoint;
    if !json {
        let mut text = format!(
            "Witness-bound bundle: {}. Publisher plus {} witnesses verified ({} required).\nCheckpoint body {} at sequence {}; continuity {}.\nBundle {}. Requested {:?}; actual {:?}; completeness {}.\n",
            if report.verified() {
                "every required predicate passed"
            } else {
                "verification failed"
            },
            pin.witnesses().len(),
            pin.required_witnesses(),
            hex(&signed.body_digest),
            cp.through_seq,
            continuity.map_or("not_checked", super::Continuity::name),
            hex(&report.digest),
            request.expected.scope,
            report.manifest.scope,
            report.manifest.completeness.label(),
        );
        if let Some(cells) = &request.balances {
            text.push_str(&format!("Recipient balance request: exactly {} stock cells.\n", cells.len()));
        } else {
            text.push_str("No specific recipient balance set was requested.\n");
        }
        for check in &report.checks {
            let (status, why) = grade(&check.grade);
            text.push_str(&format!(
                "{status}: {} [{}] {}{}\n",
                check.check,
                check.scope,
                check.subject,
                why.map_or_else(String::new, |why| format!(": {why}"))
            ));
        }
        text.push_str("A signed account index is not independently recomputed. Global freshness, full provenance, policy registration, authorization and accounting truth are not established. No pin or payload bytes were written.");
        return text;
    }
    object([
        (
            "event",
            quote(if report.verified() {
                "proof_verified"
            } else {
                "verification_failed"
            }),
        ),
        ("proof_kind", quote("witnessed_bundle")),
        ("verified", report.verified().to_string()),
        (
            "anchor",
            object([
                ("source", quote("recipient_owned_witness_policy")),
                (
                    "publisher_key_id",
                    quote(&hex(&request.anchor.publisher_id)),
                ),
                ("required_witnesses", pin.required_witnesses().to_string()),
                (
                    "verified_witnesses",
                    array(pin.witnesses().iter().map(|id| quote(&hex(id)))),
                ),
                (
                    "not_judged_signers",
                    array(signed.not_judged.iter().map(|id| quote(&hex(id)))),
                ),
                ("checkpoint_oid", quote(&hex(&signed.oid))),
                ("body_digest", quote(&hex(&signed.body_digest))),
                ("root", quote(&hex(&cp.root))),
                (
                    "policy_oid",
                    signed
                        .witness_policy_oid
                        .map_or_else(|| "null".into(), |id| quote(&hex(&id))),
                ),
                ("book_id", quote(&hex(&cp.book_id))),
                ("branch_id", quote(&hex(&cp.branch_id))),
                ("through_seq", quote(&cp.through_seq.to_string())),
                ("leaf_count", quote(&cp.leaf_count.to_string())),
            ]),
        ),
        ("bundle_digest", quote(&hex(&report.digest))),
        ("requested_scope", scope_json(&request.expected.scope)),
        ("actual_scope", scope_json(&report.manifest.scope)),
        ("balance_request", balances::json(request.balances.as_deref())),
        ("completeness", quote(report.manifest.completeness.label())),
        (
            "requirements",
            object([
                (
                    "documents",
                    quote(if request.expected.inline_documents {
                        "inline"
                    } else {
                        "commitments"
                    }),
                ),
                (
                    "receipt",
                    quote(if request.expected.publisher_receipt {
                        "publisher"
                    } else {
                        "optional"
                    }),
                ),
            ]),
        ),
        (
            "checks",
            array(report.checks.iter().map(|check| {
                let (status, why) = grade(&check.grade);
                object([
                    ("name", quote(check.check)),
                    ("scope", quote(check.scope)),
                    ("subject", quote(&check.subject)),
                    ("status", quote(status)),
                    ("detail", why.map_or_else(|| "null".into(), quote)),
                ])
            })),
        ),
        (
            "data",
            object([
                ("entries", quote(&report.summary.entries.to_string())),
                ("documents", quote(&report.summary.documents.to_string())),
                (
                    "inline_documents",
                    quote(&report.summary.inline.to_string()),
                ),
                ("balances", report.summary.balances.len().to_string()),
                ("receipt_verified", report.receipt.is_some().to_string()),
            ]),
        ),
        (
            "continuity",
            quote(continuity.map_or("not_checked", super::Continuity::name)),
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
        ("pin_written", "false".into()),
        (
            "not_checked",
            array(
                [
                    "global_freshness",
                    "policy_registration",
                    "key_rotation",
                    "witness_authorization",
                    "organizational_independence",
                    "accounting_truth",
                    "full_provenance_closure",
                    "durable_pin_storage",
                    "recipient_balance_claim_set",
                ]
                .into_iter()
                .filter(|name| *name != "recipient_balance_claim_set" || request.balances.is_none())
                .map(quote),
            ),
        ),
        ("v", "1".into()),
    ])
}
