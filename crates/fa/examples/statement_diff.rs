//! Owner-only command example over an existing book; no journal writes.
//!
//! Produce a raw replay certificate, then render the saved comparison as
//! Markdown or exact JSONL. Pass explicit sequences to reproduce a request;
//! `head` resolves once. This is an embedding example, NOT a new fa/fad/MCP
//! endpoint, signed production bundle, or authentication mechanism. The owner
//! supplies the book keys and names the principal under process authority.
//!
//! cargo run -p fa --example statement_diff -- produce BOOK KEYS PRINCIPAL_HEX32 BEFORE_SEQ AFTER_SEQ_OR_head balance-sheet PERIOD [COMPARATIVE] > comparison.cert
//! cargo run -p fa --example statement_diff -- replay BOOK KEYS PRINCIPAL_HEX32 comparison.cert markdown > comparison.md
//! cargo run -p fa --example statement_diff -- replay BOOK KEYS PRINCIPAL_HEX32 comparison.cert jsonl > comparison.jsonl

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use asupersync::Budget;
use asupersync::fs::UnixVfs;
use asupersync::runtime::RuntimeBuilder;
use fa::{
    AsyncBook, BookKeys, Capability, Entropy, MAX_STATEMENT_DIFF_CERTIFICATE_BYTES,
    StatementDefinition, StatementDiffCertificate, StatementDiffRequest, StatementSelection,
};
use fa_journal::Refusal;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

const HELP: &str = "Owner-only historical statement comparison example

Produce a raw binary replay certificate on stdout:
  statement_diff produce BOOK KEYS PRINCIPAL_HEX32 BEFORE_SEQ AFTER_SEQ_OR_head DEFINITION PERIOD [COMPARATIVE]
Replay both sources, then emit a reviewable workpaper on stdout:
  statement_diff replay BOOK KEYS PRINCIPAL_HEX32 CERTIFICATE markdown|jsonl

DEFINITION is balance-sheet or income-statement. All numbers are exact native
mantissas. Comparatives are effective periods, not alternative known-at dates.
Trust and principal authentication belong to this embedding's owner; the keys
are not emitted. No statement issuance, approval or signed bundle is claimed.
No journal writes occur. Save the certificate to replay the exact selection
later. Use shell redirection only to destinations you intend to write.
Exit codes: 0 success/help; 2 usage; 4 book/key open; 5 I/O/foundation;
3/7 lawful refusal; 8 failed verification. Diagnostics go to stderr.";

struct Failure {
    exit: u8,
    message: String,
}
impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            exit: 2,
            message: message.into(),
        }
    }
    fn at(exit: u8, message: impl std::fmt::Display) -> Self {
        Self {
            exit,
            message: message.to_string(),
        }
    }
}
impl From<Refusal> for Failure {
    fn from(r: Refusal) -> Self {
        Self::at(r.exit, r)
    }
}

enum Mode {
    Produce(StatementDiffRequest),
    Replay { file: PathBuf, markdown: bool },
}
struct Request {
    book: PathBuf,
    keys: PathBuf,
    principal: VId,
    mode: Mode,
}

fn text(arg: &OsString) -> Result<&str, Failure> {
    arg.to_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Failure::usage("a semantic argument is not nonempty UTF-8"))
}
fn sequence(arg: &OsString) -> Result<CommitSeq, Failure> {
    let value = text(arg)?;
    if value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Failure::usage(
            "a sequence is an unsigned decimal integer, never a date or instant",
        ));
    }
    value
        .parse::<u64>()
        .map(CommitSeq)
        .map_err(|_| Failure::usage("sequence exceeds u64"))
}
fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let mode = args.first().map(text).transpose()?.unwrap_or("");
    if !((mode == "produce" && (args.len() == 8 || args.len() == 9))
        || (mode == "replay" && args.len() == 6))
    {
        return Err(Failure::usage(HELP));
    }
    let principal = text(&args[3])?;
    if principal.len() != 32 || !principal.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Failure::usage(
            "principal requires exactly 32 hexadecimal digits",
        ));
    }
    let principal = VId(u128::from_str_radix(principal, 16).map_err(|e| Failure::at(2, e))?);
    if args[1].is_empty() || args[2].is_empty() {
        return Err(Failure::usage("book and key file paths must be nonempty"));
    }
    let mode = if mode == "produce" {
        let before = sequence(&args[4])?;
        let after = if args[5] == "head" {
            None
        } else {
            Some(sequence(&args[5])?)
        };
        if after.is_some_and(|s| s < before) {
            return Err(Failure::usage("before must not follow after"));
        }
        let definition =
            StatementDefinition::embedded(text(&args[6])?).map_err(|e| Failure::at(2, e))?;
        let period = |arg: &OsString| -> Result<String, Failure> {
            let s = text(arg)?;
            if s.len() > 128 {
                return Err(Failure::usage("period code exceeds 128 bytes"));
            }
            Ok(s.to_string())
        };
        let comparative = args.get(8).map(period).transpose()?.into_iter().collect();
        Mode::Produce(StatementDiffRequest {
            selection: StatementSelection {
                definition,
                periods: vec![period(&args[7])?],
                comparative,
            },
            before,
            after,
        })
    } else {
        let markdown = match text(&args[5])? {
            "markdown" => true,
            "jsonl" => false,
            _ => return Err(Failure::usage("replay output must be markdown or jsonl")),
        };
        if args[4].is_empty() {
            return Err(Failure::usage("certificate path must be nonempty"));
        }
        Mode::Replay {
            file: PathBuf::from(&args[4]),
            markdown,
        }
    };
    Ok(Request {
        book: PathBuf::from(&args[1]),
        keys: PathBuf::from(&args[2]),
        principal,
        mode,
    })
}

fn run(request: Request) -> Result<(), Failure> {
    let runtime = RuntimeBuilder::new()
        .build()
        .map_err(|e| Failure::at(5, format!("runtime: {e:?}")))?;
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let vfs = UnixVfs::new();
    let keys = runtime
        .block_on(BookKeys::load_with_vfs(&cx.query(), &vfs, &request.keys))
        .map_err(|e| Failure::at(4, e))?;
    let book = runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs,
            &request.book,
            keys,
            Entropy::production(),
        ))
        .map_err(|e| Failure::at(4, e))?;
    let capability = Capability::embedded(request.principal, &["read", "produce"])
        .map_err(|e| Failure::at(7, e))?;
    let output = match request.mode {
        Mode::Produce(selection) => {
            let result = book
                .certify_statement_diff(&cx, request.principal, &capability, &selection)
                .map_err(|e| Failure::at(5, e))??;
            result.certificate.canonical_bytes()?
        }
        Mode::Replay { file, markdown } => {
            // External transport input, bounded before any decoder allocation.
            let bytes = cx
                .query()
                .with_restriction(|| -> Result<Vec<u8>, Failure> {
                    let mut bytes = Vec::new();
                    let input = File::open(&file).map_err(|e| Failure::at(5, e))?;
                    let max = MAX_STATEMENT_DIFF_CERTIFICATE_BYTES as u64;
                    if input.metadata().map_err(|e| Failure::at(5, e))?.len() > max {
                        return Err(Failure::at(8, "certificate exceeds 64 MiB"));
                    }
                    input
                        .take(max + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|e| Failure::at(5, e))?;
                    if bytes.len() > MAX_STATEMENT_DIFF_CERTIFICATE_BYTES {
                        return Err(Failure::at(8, "certificate grew past 64 MiB"));
                    }
                    Ok(bytes)
                })?;
            let certificate = StatementDiffCertificate::decode(&bytes)?;
            let workpaper = book
                .statement_diff_workpaper(&cx, request.principal, &capability, &certificate)
                .map_err(|e| Failure::at(5, e))??;
            if markdown {
                workpaper.markdown().as_bytes().to_vec()
            } else {
                workpaper.jsonl().as_bytes().to_vec()
            }
        }
    };
    // No output is attempted until the entire computation/replay succeeded.
    cx.commit()
        .checkpoint()
        .map_err(|e| Failure::at(5, format!("cancelled: {e:?}")))?;
    cx.commit().with_restriction(|| {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&output)
            .and_then(|()| stdout.flush())
            .map_err(|e| Failure::at(5, e))
    })
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        return match writeln!(std::io::stdout().lock(), "{HELP}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(5),
        };
    }
    match parse(&args).and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "statement_diff: {}",
                failure.message
            );
            ExitCode::from(failure.exit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(|part| OsString::from(*part)).collect()
    }
    fn principal() -> &'static str {
        "00000000000000000000000000000007"
    }

    #[test]
    fn both_modes_validate_their_complete_request_without_opening_files() {
        let request = parse(&args(&[
            "produce",
            "book",
            "keys",
            principal(),
            "20",
            "head",
            "balance-sheet",
            "FY2026-P03",
            "FY2025-P03",
        ]))
        .ok()
        .unwrap();
        let Mode::Produce(request) = request.mode else {
            panic!("wrong mode");
        };
        assert_eq!(request.before, CommitSeq(20));
        assert_eq!(request.after, None);
        assert_eq!(request.selection.comparative, vec!["FY2025-P03"]);
        for output in ["markdown", "jsonl"] {
            assert!(
                parse(&args(&[
                    "replay",
                    "book",
                    "keys",
                    principal(),
                    "certificate",
                    output
                ]))
                .is_ok()
            );
        }
    }

    #[test]
    fn unknown_partial_and_nonnumeric_requests_fail_before_io() {
        for before in ["-1", "+1", "1.0", "18446744073709551616", "2026-03-01"] {
            assert!(
                parse(&args(&[
                    "produce",
                    "book",
                    "keys",
                    principal(),
                    before,
                    "head",
                    "balance-sheet",
                    "FY2026-P03"
                ]))
                .is_err()
            );
        }
        assert!(
            parse(&args(&[
                "produce",
                "book",
                "keys",
                principal(),
                "20",
                "19",
                "balance-sheet",
                "FY2026-P03"
            ]))
            .is_err()
        );
        assert!(
            parse(&args(&[
                "produce",
                "book",
                "keys",
                "7",
                "20",
                "21",
                "balance-sheet",
                "FY2026-P03"
            ]))
            .is_err()
        );
        assert!(
            parse(&args(&[
                "replay",
                "book",
                "keys",
                principal(),
                "certificate",
                "csv"
            ]))
            .is_err()
        );
        assert!(parse(&[]).is_err());
    }
}
