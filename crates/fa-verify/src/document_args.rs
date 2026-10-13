//! Offline document-disclosure command with a recipient-owned trust anchor.
//! Parsing completes before any input file is opened. A successful report
//! contains metadata only; neither stdout nor diagnostics dump source bytes.

use std::ffi::OsString;
use std::path::PathBuf;

use fa_verify::disclosure::{self, MAX_DISCLOSURE_CHUNKS};

use crate::{Failure, array, hex, object, quote, read_bounded};

struct Request {
    proof: PathBuf,
    commitment: PathBuf,
    indexes: Vec<u64>,
}

fn indexes(value: &str) -> Result<Vec<u64>, Failure> {
    if value.len() > MAX_DISCLOSURE_CHUNKS * 21 {
        return Err(Failure::usage("--chunks exceeds the bounded recipient request"));
    }
    let mut indexes = Vec::new();
    for token in value.split(',') {
        if indexes.len() == MAX_DISCLOSURE_CHUNKS {
            return Err(Failure::usage(format!(
                "--chunks admits at most {MAX_DISCLOSURE_CHUNKS} indexes"
            )));
        }
        if token.is_empty() || token.len() > 20 || !token.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Failure::usage(
                "--chunks requires comma-separated unsigned decimal indexes, e.g. 0,4",
            ));
        }
        indexes.push(token.parse::<u64>().map_err(|_| {
            Failure::usage("a --chunks index exceeds u64")
        })?);
    }
    disclosure::validate_request(&indexes)
        .map_err(|error| Failure::usage(error.to_string()))?;
    Ok(indexes)
}

fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let (mut proof, mut commitment, mut requested) = (None, None, None);
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
        let name = match argument.to_str() {
            Some("--proof") => "--proof",
            Some("--document-commit") => "--document-commit",
            Some("--chunks") => "--chunks",
            _ => return Err(Failure::usage(format!(
                "unknown document argument {argument:?}; use --proof FILE --document-commit TRUSTED_FILE --chunks 0,4"
            ))),
        };
        let value = args.get(index + 1)
            .ok_or_else(|| Failure::usage(format!("{name} requires a value")))?;
        if value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--")) {
            return Err(Failure::usage(format!("{name} requires a value")));
        }
        if name == "--chunks" {
            if requested.is_some() {
                return Err(Failure::usage("--chunks may be supplied only once"));
            }
            requested = Some(indexes(value.to_str().ok_or_else(|| {
                Failure::usage("--chunks must be an ASCII decimal index list")
            })?)?);
        } else {
            let slot = if name == "--proof" { &mut proof } else { &mut commitment };
            if slot.is_some() {
                return Err(Failure::usage(format!("{name} may be supplied only once")));
            }
            *slot = Some(PathBuf::from(value));
        }
        index += 2;
    }
    Ok(Request {
        proof: proof.ok_or_else(|| Failure::usage("--proof is required"))?,
        commitment: commitment.ok_or_else(|| Failure::usage(
            "--document-commit is required; obtain and trust the 32 raw commitment bytes independently"
        ))?,
        indexes: requested.ok_or_else(|| Failure::usage(
            "--chunks is required; specify the recipient's exact request, never infer it from the proof"
        ))?,
    })
}

pub(super) fn run(args: &[OsString], json: bool) -> Result<String, Failure> {
    let request = parse(args)?;
    let bytes = read_bounded(&request.commitment, 32)?;
    let trusted: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        Failure::verification("--document-commit must contain exactly 32 raw bytes, not hex text")
    })?;
    let proof = read_bounded(&request.proof, disclosure::MAX_PROOF_BYTES)?;
    let report = disclosure::verify(&proof, &request.indexes, &trusted)
        .map_err(|error| Failure::verification(error.to_string()))?;
    if !json {
        return Ok(format!(
            "Verified document disclosure (scope: {}): {} requested chunks, kind {}, document length {} bytes.\nTrusted doc_commit: {}.\nSignatures, provenance, authorization, undisclosed bytes and production completeness were not verified.",
            report.scope, report.chunks.len(), report.kind, report.document_length, hex(&trusted)
        ));
    }
    Ok(object([
        ("anchor", object([
            ("format", quote("raw_document_commitment")),
            ("signature_verification", quote("not_performed")),
            ("source", quote("operator_trusted_document_commitment")),
        ])),
        ("checks", array(["requested_chunk_set", "document_chunk_membership"].map(|name| {
            object([("name", quote(name)), ("status", quote("pass"))])
        }))),
        ("data", object([
            ("chunks", array(report.chunks.iter().map(|chunk| object([
                ("byte_length", chunk.byte_length.to_string()),
                ("index", quote(&chunk.index.to_string())),
            ])))),
            ("document_kind", report.kind.to_string()),
            ("document_length_bytes", quote(&report.document_length.to_string())),
            ("requested_chunks", request.indexes.len().to_string()),
        ])),
        ("document_commit", quote(&hex(&trusted))),
        ("event", quote("proof_verified")),
        ("proof_kind", quote("document")),
        ("scope", quote(report.scope)),
        ("v", "1".into()),
        ("verified", "true".into()),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<OsString> {
        ["document", "--proof", "absent-proof", "--document-commit", "absent-anchor"]
            .into_iter().chain(extra.iter().copied()).map(OsString::from).collect()
    }

    #[test]
    fn recipient_indexes_are_exact_bounded_and_never_sorted_or_deduplicated() {
        let valid = indexes("0,4,18446744073709551615")
            .unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(valid, vec![0, 4, u64::MAX]);
        for value in ["", ",", "0,", ",0", "0,,1", "1,0", "0,0", "-1", "+1",
            "0, 1", "0x10", "18446744073709551616", "1.0", "０"]
        {
            assert!(indexes(value).is_err(), "{value}");
        }
        let maximum = (0..MAX_DISCLOSURE_CHUNKS).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        assert_eq!(indexes(&maximum).unwrap_or_else(|e| panic!("{}", e.message)).len(), MAX_DISCLOSURE_CHUNKS);
        assert!(indexes(&format!("{maximum},{MAX_DISCLOSURE_CHUNKS}")).is_err());
    }

    #[test]
    fn missing_duplicate_and_foreign_options_refuse_before_any_file_observation() {
        let valid = parse(&args(&["--chunks", "0,4", "--json"]))
            .unwrap_or_else(|error| panic!("{}", error.message));
        assert_eq!(valid.indexes, vec![0, 4]);
        for extra in [
            vec![], vec!["--chunks"], vec!["--chunks", "1,0"],
            vec!["--chunks", "0", "--chunks", "0"],
            vec!["--chunks", "0", "--proof", "another"],
            vec!["--chunks", "0", "--document-commit", "another"],
            vec!["--chunks", "0", "--json", "--json"],
            vec!["--chunks", "0", "--checkpoint", "checkpoint"],
            vec!["--chunks", "0", "--expect-account", "0"],
        ] {
            let error = run(&args(&extra), true).err().expect("usage refusal");
            assert_eq!(error.exit, 2, "{:?}: {}", extra, error.message);
        }
    }
}
