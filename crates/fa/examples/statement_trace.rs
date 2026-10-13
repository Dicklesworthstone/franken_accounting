//! Owner-side attribution workflow over an existing book. This is not a new
//! fa/fad/MCP endpoint or principal authentication scheme. The process owner
//! supplies the book keys and principal and receives unsigned retained-history
//! replay evidence, never a statement-issuance or case-approval assertion.
//!
//! cargo run -p fa --example statement_trace -- produce BOOK KEYS PRINCIPAL_HEX32 BEFORE_SEQ AFTER_SEQ_OR_head MAX_PUBLICATIONS balance-sheet PERIOD [COMPARATIVE] > trace.cert
//! cargo run -p fa --example statement_trace -- extend BOOK KEYS PRINCIPAL_HEX32 comparison.cert MAX_PUBLICATIONS > trace.cert
//! cargo run -p fa --example statement_trace -- replay BOOK KEYS PRINCIPAL_HEX32 trace.cert > trace.jsonl

#![forbid(unsafe_code)]

use asupersync::Budget;
use asupersync::fs::UnixVfs;
use asupersync::runtime::RuntimeBuilder;
use fa::{
    AsyncBook, BookKeys, Capability, Entropy, MAX_STATEMENT_DIFF_CERTIFICATE_BYTES,
    MAX_STATEMENT_TRACE_CERTIFICATE_BYTES, MAX_STATEMENT_TRACE_PUBLICATIONS, StatementDefinition,
    StatementDiffCertificate, StatementDiffRequest, StatementSelection, StatementTraceCertificate,
    StatementTraceRequest,
};
use fa_journal::Refusal;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const HELP: &str = "Owner-side statement publication attribution

Produce a complete adjacent-publication certificate:
  statement_trace produce BOOK KEYS PRINCIPAL_HEX32 BEFORE_SEQ AFTER_SEQ_OR_head MAX_PUBLICATIONS DEFINITION PERIOD [COMPARATIVE]
Extend a saved statement comparison without replacing either endpoint:
  statement_trace extend BOOK KEYS PRINCIPAL_HEX32 COMPARISON_CERTIFICATE MAX_PUBLICATIONS
Replay the complete source chain, then emit exact JSONL:
  statement_trace replay BOOK KEYS PRINCIPAL_HEX32 TRACE_CERTIFICATE

DEFINITION is balance-sheet or income-statement. MAX_PUBLICATIONS is 1..=256;
the interval must fit, or the request is refused without partial output.
Comparatives are effective periods, not recorded sequences. No journal
writes occur. This owner-controlled process is responsible for principal
identity and key custody; it does not authenticate remote callers. All
certificates are unsigned retained-history computations, not case approval,
statement issuance or outsider completeness proofs. Entry links identify
associated records, not an allocation of an atomic batch's delta to entries.
Outputs go to stdout only after complete success; diagnostics go to stderr.
Use shell redirection only to destinations you intend to write.
Exit codes: 0 success/help; 2 usage; 4 book/key open; 5 I/O/foundation;
3/7 lawful refusal; 8 failed verification.";

#[derive(Debug)]
struct Failure {
    exit: u8,
    message: String,
}
impl Failure {
    fn at(exit: u8, message: impl std::fmt::Display) -> Self {
        Self {
            exit,
            message: message.to_string(),
        }
    }
    fn usage(message: impl std::fmt::Display) -> Self {
        Self::at(2, message)
    }
}
impl From<Refusal> for Failure {
    fn from(r: Refusal) -> Self {
        Self::at(r.exit, r)
    }
}

enum Mode {
    Produce(StatementTraceRequest),
    Extend {
        file: PathBuf,
        max_publications: usize,
    },
    Replay {
        file: PathBuf,
    },
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
        .ok_or_else(|| Failure::usage("semantic arguments require nonempty UTF-8"))
}
fn number(arg: &OsString) -> Result<u64, Failure> {
    let value = text(arg)?;
    if value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::usage(
            "sequences and limits require unsigned decimal integers",
        ));
    }
    value
        .parse()
        .map_err(|_| Failure::usage("integer exceeds u64"))
}
fn limit(arg: &OsString) -> Result<usize, Failure> {
    let n = number(arg)?;
    if n == 0 || n > MAX_STATEMENT_TRACE_PUBLICATIONS as u64 {
        return Err(Failure::usage("MAX_PUBLICATIONS must be 1..=256"));
    }
    Ok(n as usize)
}
fn parse(args: &[OsString]) -> Result<Request, Failure> {
    let mode = args.first().map(text).transpose()?.unwrap_or("");
    if !((mode == "produce" && (args.len() == 9 || args.len() == 10))
        || (mode == "extend" && args.len() == 6)
        || (mode == "replay" && args.len() == 5))
    {
        return Err(Failure::usage(HELP));
    }
    let principal = text(&args[3])?;
    if principal.len() != 32 || !principal.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Failure::usage(
            "principal requires exactly 32 hexadecimal digits",
        ));
    }
    let principal = VId(u128::from_str_radix(principal, 16).map_err(Failure::usage)?);
    if args[1].is_empty() || args[2].is_empty() {
        return Err(Failure::usage("book and key paths must be nonempty"));
    }
    let mode = match mode {
        "produce" => {
            let before = CommitSeq(number(&args[4])?);
            let after = if args[5] == "head" {
                None
            } else {
                Some(CommitSeq(number(&args[5])?))
            };
            let max_publications = limit(&args[6])?;
            if after.is_some_and(|at| at < before || at.0 - before.0 > max_publications as u64) {
                return Err(Failure::usage(
                    "ordered sequence interval must fit MAX_PUBLICATIONS",
                ));
            }
            let definition =
                StatementDefinition::embedded(text(&args[7])?).map_err(Failure::usage)?;
            let period = |arg: &OsString| -> Result<String, Failure> {
                let period = text(arg)?;
                if period.len() > 128 {
                    return Err(Failure::usage("period code exceeds 128 bytes"));
                }
                Ok(period.to_string())
            };
            Mode::Produce(StatementTraceRequest {
                comparison: StatementDiffRequest {
                    selection: StatementSelection {
                        definition,
                        periods: vec![period(&args[8])?],
                        comparative: args.get(9).map(period).transpose()?.into_iter().collect(),
                    },
                    before,
                    after,
                },
                max_publications,
            })
        }
        "extend" | "replay" => {
            if args[4].is_empty() {
                return Err(Failure::usage("certificate path must be nonempty"));
            }
            let file = PathBuf::from(&args[4]);
            if mode == "extend" {
                Mode::Extend {
                    file,
                    max_publications: limit(&args[5])?,
                }
            } else {
                Mode::Replay { file }
            }
        }
        _ => return Err(Failure::usage(HELP)),
    };
    Ok(Request {
        book: PathBuf::from(&args[1]),
        keys: PathBuf::from(&args[2]),
        principal,
        mode,
    })
}

fn read_certificate(cx: &PurposeContexts, path: &Path, max: usize) -> Result<Vec<u8>, Failure> {
    let query = cx.query();
    query
        .checkpoint()
        .map_err(|e| Failure::at(5, format!("cancelled: {e:?}")))?;
    let bytes = query.with_restriction(|| {
        let input = File::open(path).map_err(|e| Failure::at(5, e))?;
        if input.metadata().map_err(|e| Failure::at(5, e))?.len() > max as u64 {
            return Err(Failure::at(8, "certificate exceeds its 64 MiB bound"));
        }
        let mut bytes = Vec::new();
        input
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Failure::at(5, e))?;
        if bytes.len() > max {
            return Err(Failure::at(8, "certificate grew past its input bound"));
        }
        Ok(bytes)
    })?;
    query
        .checkpoint()
        .map_err(|e| Failure::at(5, format!("cancelled: {e:?}")))?;
    Ok(bytes)
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
        Mode::Produce(selection) => book
            .certify_statement_trace(&cx, request.principal, &capability, &selection)
            .map_err(|e| Failure::at(5, e))??
            .certificate
            .canonical_bytes()?,
        Mode::Extend {
            file,
            max_publications,
        } => {
            let bytes = read_certificate(&cx, &file, MAX_STATEMENT_DIFF_CERTIFICATE_BYTES)?;
            let comparison = StatementDiffCertificate::decode(&bytes)?;
            book.certify_statement_trace_from_diff(
                &cx,
                request.principal,
                &capability,
                &comparison,
                max_publications,
            )
            .map_err(|e| Failure::at(5, e))??
            .certificate
            .canonical_bytes()?
        }
        Mode::Replay { file } => {
            let bytes = read_certificate(&cx, &file, MAX_STATEMENT_TRACE_CERTIFICATE_BYTES)?;
            let certificate = StatementTraceCertificate::decode(&bytes)?;
            book.statement_trace_jsonl(&cx, request.principal, &capability, &certificate)
                .map_err(|e| Failure::at(5, e))??
                .into_bytes()
        }
    };
    cx.commit()
        .checkpoint()
        .map_err(|e| Failure::at(5, format!("cancelled: {e:?}")))?;
    cx.commit().with_restriction(|| {
        let mut out = std::io::stdout().lock();
        out.write_all(&output)
            .and_then(|()| out.flush())
            .map_err(|e| Failure::at(5, e))
    })
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
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
                "statement_trace: {}",
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
        parts.iter().map(|s| OsString::from(*s)).collect()
    }
    const PRINCIPAL: &str = "00000000000000000000000000000007";
    #[test]
    fn all_three_modes_validate_without_file_access() {
        let request = parse(&args(&[
            "produce",
            "book",
            "keys",
            PRINCIPAL,
            "10",
            "head",
            "128",
            "balance-sheet",
            "FY2026-P03",
            "FY2025-P03",
        ]))
        .unwrap();
        let trace = match request.mode {
            Mode::Produce(trace) => Some(trace),
            _ => None,
        }
        .expect("produce mode");
        assert_eq!(trace.comparison.before, CommitSeq(10));
        assert_eq!(trace.comparison.after, None);
        assert_eq!(trace.max_publications, 128);
        assert_eq!(trace.comparison.selection.comparative, vec!["FY2025-P03"]);
        assert!(
            parse(&args(&[
                "extend",
                "book",
                "keys",
                PRINCIPAL,
                "diff.cert",
                "256"
            ]))
            .is_ok()
        );
        assert!(parse(&args(&["replay", "book", "keys", PRINCIPAL, "trace.cert"])).is_ok());
    }
    #[test]
    fn invalid_limits_coordinates_and_unknown_modes_are_usage_errors_before_io() {
        for limit in ["0", "257", "-1", "+1", "1.5", "18446744073709551616"] {
            assert!(
                parse(&args(&[
                    "extend",
                    "book",
                    "keys",
                    PRINCIPAL,
                    "diff.cert",
                    limit
                ]))
                .is_err()
            );
        }
        for after in ["9", "267", "-1", "2026-03-20", "18446744073709551616"] {
            assert!(
                parse(&args(&[
                    "produce",
                    "book",
                    "keys",
                    PRINCIPAL,
                    "10",
                    after,
                    "256",
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
                PRINCIPAL,
                "10",
                "11",
                "1",
                "unknown",
                "FY2026-P03"
            ]))
            .is_err()
        );
        assert!(parse(&args(&["replay", "book", "keys", "7", "trace.cert"])).is_err());
        assert!(
            parse(&args(&[
                "replay",
                "book",
                "keys",
                PRINCIPAL,
                "trace.cert",
                "extra"
            ]))
            .is_err()
        );
        assert!(parse(&args(&["delete", "book", "keys", PRINCIPAL, "trace.cert"])).is_err());
        assert!(parse(&[]).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn file_paths_keep_non_utf8_bytes_but_semantic_arguments_do_not() {
        use std::os::unix::ffi::OsStringExt;
        let mut values = args(&["replay", "book", "keys", PRINCIPAL, "trace.cert"]);
        values[1] = OsString::from_vec(vec![b'b', 0xff]);
        values[4] = OsString::from_vec(vec![b't', 0xfe]);
        assert!(parse(&values).is_ok());
        values[3] = OsString::from_vec(vec![0xff]);
        assert!(parse(&values).is_err());
    }
}
