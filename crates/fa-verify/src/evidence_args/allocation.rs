//! Offline allocation verification under recipient-owned entry/driver inputs.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::{Failure, array, hex, object, quote, read_bounded, read_checkpoint};
use fa_verify::evidence::inventory::allocation::{
    MAX_ALLOCATION_INPUT_BYTES, MAX_BASIS_BYTES, VerifiedAllocation, verify_allocation_for,
};

const HELP: &str = "Usage:
  fa-verify evidence allocation --proof INCLUSION --checkpoint TRUSTED_FILE \\
    --expect-entry HEX64 --expect-basis WORKPAPER [--json]

All four value options are required exactly once. The inclusion proof must
contain the full entry record. The checkpoint is a separately trusted raw
80-byte checkpoint; HEX64 is an independently chosen entry digest. WORKPAPER
contains the exact raw AllocationPosting::basis_bytes reviewed by the recipient,
not a document wrapper, a hex string, or a basis learned from the proof.

Verifies leaf inclusion, the exact Source-role Workpaper citation, retained
law/basis digests, and every ordered native leg using independent arithmetic.
Supports LargestRemainder, ProRataResidualToNamed (all nine rounding laws),
Waterfall and EqualSplitResidualFirst. Zero shares remain in the target list;
negative residual corrections must have the exact opposite posting direction.
Both signed conservation and representable gross turnover are required.

This does NOT verify driver truth/provenance, account legality, unit definitions,
current authority, approvals, period admission, limits, later reversals,
signatures, or journal/production completeness. Inclusion is not authorization.
Output includes selected account/share metadata, not raw driver bytes, driver
weights, or protected descriptions. Treat the workpaper and report as confidential.

Driver bytes are limited to 65,452 bytes, targets to 1,024, and proof plus
driver bytes together to 64 MiB. No book, keys or network are required.
Exit codes: 0 verified/help; 2 usage; 5 file/output I/O; 8 verification failed.";

struct Request {
    proof: PathBuf,
    checkpoint: PathBuf,
    basis: PathBuf,
    entry_digest: [u8; 32],
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let (mut proof, mut checkpoint, mut basis, mut entry) = (None, None, None, None);
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
            .ok_or_else(|| Failure::usage("unknown allocation option"))?;
        if !matches!(
            name,
            "--proof" | "--checkpoint" | "--expect-entry" | "--expect-basis"
        ) {
            return Err(Failure::usage(
                "unknown allocation option; run fa-verify evidence allocation --help",
            ));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--")) {
            return Err(Failure::usage(format!(
                "{name} requires a value; use ./ before filenames beginning with --"
            )));
        }
        let slot = match name {
            "--proof" => &mut proof,
            "--checkpoint" => &mut checkpoint,
            "--expect-basis" => &mut basis,
            _ => &mut entry,
        };
        if slot.replace(value).is_some() {
            return Err(Failure::usage(format!("{name} may be supplied only once")));
        }
        index += 2;
    }
    let proof = proof.ok_or_else(|| Failure::usage("--proof is required"))?;
    let checkpoint = checkpoint.ok_or_else(|| Failure::usage("--checkpoint is required"))?;
    let basis = basis
        .ok_or_else(|| Failure::usage("--expect-basis is required independently of the proof"))?;
    let entry = entry
        .ok_or_else(|| Failure::usage("--expect-entry is required independently of the proof"))?;
    let entry = entry
        .to_str()
        .ok_or_else(|| Failure::usage("--expect-entry must be ASCII hexadecimal"))?;
    Ok(Request {
        proof: proof.into(),
        checkpoint: checkpoint.into(),
        basis: basis.into(),
        entry_digest: super::digest(entry)?,
    })
}

pub(super) fn run(args: &[OsString], json: bool) -> Result<String, Failure> {
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h" | "help")) {
        return Ok(HELP.into());
    }
    let request = parse(args)?; // No file has been observed before complete parsing.
    let checkpoint = read_checkpoint(&request.checkpoint)?;
    let basis = read_bounded(&request.basis, MAX_BASIS_BYTES)?;
    let remaining = MAX_ALLOCATION_INPUT_BYTES
        .checked_sub(basis.len())
        .ok_or_else(|| Failure::verification("allocation input budget exhausted"))?;
    let proof = read_bounded(&request.proof, remaining)?;
    let verified = verify_allocation_for(&proof, &checkpoint, &request.entry_digest, &basis)
        .map_err(|error| Failure::verification(error.to_string()))?;
    render(&verified, json)
}

fn side(debit: bool) -> &'static str {
    if debit { "Debit" } else { "Credit" }
}

fn render(report: &VerifiedAllocation, json: bool) -> Result<String, Failure> {
    let inclusion = &report.inclusion;
    let basis = &report.basis;
    let output = if !json {
        let mut text = format!(
            "Verified allocation: entry {} at sequence {} (scope: inclusion; arithmetic: native allocation).\nLaw {} version 1; source {:032x} {}; total {} in native unit {}.\nDriver commitment {}; basis digest {}.\n",
            hex(&inclusion.envelope.record_digest),
            inclusion.envelope.commit_seq,
            basis.law,
            basis.source,
            side(basis.source_debit),
            basis.total,
            basis.unit,
            hex(&report.driver.doc_commit),
            hex(&report.basis_digest),
        );
        for (index, (target, share)) in basis.targets.iter().zip(&report.shares).enumerate() {
            let posting = if *share == 0 {
                "NoLeg"
            } else {
                side(if *share < 0 {
                    basis.source_debit
                } else {
                    !basis.source_debit
                })
            };
            text.push_str(&format!(
                "target {index} account {:032x} signed_share {share} posting {posting}\n",
                target.account
            ));
        }
        text.push_str("Only inclusion, allocation arithmetic and the exact driver citation were checked. Driver truth/provenance, account legality, unit definitions, authority, approvals, period admission, limits, later reversals, signatures and completeness were NOT checked. Raw driver bytes, weights and protected descriptions are not printed.");
        text
    } else {
        let checkpoint = &inclusion.checkpoint;
        object([
            (
                "anchor",
                object([
                    ("source", quote("operator_trusted_checkpoint")),
                    ("signature_verification", quote("not_performed")),
                ]),
            ),
            (
                "checkpoint",
                object([
                    ("book_id", quote(&hex(&checkpoint.book_id))),
                    ("branch_id", quote(&hex(&checkpoint.branch_id))),
                    ("root", quote(&hex(&checkpoint.root))),
                    ("through_seq", quote(&checkpoint.through_seq.to_string())),
                    ("leaf_count", quote(&checkpoint.leaf_count.to_string())),
                ]),
            ),
            (
                "checks",
                array(
                    [
                        "requested_entry_digest",
                        "record_recomputation",
                        "leaf_inclusion",
                        "exact_requested_driver",
                        "source_workpaper_citation",
                        "law_and_basis_digests",
                        "independent_allocation_arithmetic",
                        "exact_ordered_legs_and_dimensions",
                        "signed_conservation",
                        "representable_journal_turnover",
                        "complete_entry_frame",
                    ]
                    .map(|name| object([("name", quote(name)), ("status", quote("pass"))])),
                ),
            ),
            (
                "data",
                object([
                    (
                        "entry_digest",
                        quote(&hex(&inclusion.envelope.record_digest)),
                    ),
                    (
                        "recorded_at",
                        quote(&inclusion.envelope.commit_seq.to_string()),
                    ),
                    ("leaf_index", quote(&inclusion.leaf_index.to_string())),
                    ("law_id", quote(&basis.law.to_string())),
                    ("law_version", quote("1")),
                    ("law_digest", quote(&hex(&report.law_digest))),
                    ("basis_digest", quote(&hex(&report.basis_digest))),
                    ("driver_oid", quote(&hex(&report.driver.document_oid))),
                    ("driver_commitment", quote(&hex(&report.driver.doc_commit))),
                    ("source_account", quote(&format!("{:032x}", basis.source))),
                    ("source_side", quote(side(basis.source_debit))),
                    ("native_unit_id", quote(&basis.unit.to_string())),
                    ("total_mantissa", quote(&basis.total.to_string())),
                    ("target_count", quote(&basis.targets.len().to_string())),
                    (
                        "targets",
                        array(basis.targets.iter().zip(&report.shares).enumerate().map(
                            |(index, (target, share))| {
                                object([
                                    ("ordinal", quote(&index.to_string())),
                                    ("account", quote(&format!("{:032x}", target.account))),
                                    ("signed_share", quote(&share.to_string())),
                                    (
                                        "posting_side",
                                        if *share == 0 {
                                            "null".into()
                                        } else {
                                            quote(side(if *share < 0 {
                                                basis.source_debit
                                            } else {
                                                !basis.source_debit
                                            }))
                                        },
                                    ),
                                ])
                            },
                        )),
                    ),
                ]),
            ),
            ("event", quote("proof_verified")),
            ("proof_kind", quote("allocation")),
            ("scope", quote("inclusion")),
            (
                "computation_scope",
                quote("native_allocation_recomputation"),
            ),
            ("request_check", quote("entry_and_exact_driver")),
            (
                "not_checked",
                array(
                    [
                        "driver_truth",
                        "driver_provenance",
                        "account_legality",
                        "unit_definitions",
                        "authorization",
                        "approvals",
                        "period_admission",
                        "limits",
                        "later_reversals",
                        "signatures",
                        "journal_completeness",
                        "production_completeness",
                    ]
                    .map(quote),
                ),
            ),
            ("v", "1".into()),
            ("verified", "true".into()),
        ])
    };
    // 1024 fixed-width numeric target rows bound construction itself. This
    // additional ceiling prevents later renderer growth from leaking a prefix.
    if output.len() > 512 * 1024 {
        return Err(Failure::verification(
            "allocation report exceeds its output bound",
        ));
    }
    Ok(output)
}
