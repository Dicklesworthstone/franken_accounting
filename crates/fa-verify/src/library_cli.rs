//! Routing to the library's command line ([`fa_verify::cli`]): signed
//! `TransparencyCheckpoint` anchors (`--key`), scope-index, state, document
//! commitment and evidence-bundle verification, positional-file grammar, and
//! the explicit `--unsigned-checkpoint` anchor. The raw `--proof/--checkpoint`
//! grammar, `document` and `redacted-view` stay with this binary's own parser.
//!
//! Inputs are read with the library's size bound checked before allocation,
//! and a file name that is not UTF-8 stays usable: such an argument reaches
//! the library under a NUL-prefixed placeholder (a real path never contains
//! NUL) that is resolved back to the original name when the file is opened.

mod witness;

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use fa_verify::cli::{EXIT_IO, MAX_INPUT_BYTES};

const PLACEHOLDER: &str = "\u{0}non-UTF-8 argument #";

/// Commands only the library verifies.
const LIBRARY_COMMANDS: [&str; 9] = [
    "access-log",
    "state",
    "checkpoint",
    "scope",
    "doc-commit",
    "bundle",
    "report",
    "ads",
    "witness",
];
/// Commands both grammars verify; the raw grammar always names `--proof`.
const SHARED_COMMANDS: [&str; 4] = ["inclusion", "prefix", "balance", "consistency"];
/// Commands only this binary's own parser verifies.
const RAW_ONLY_COMMANDS: [&str; 3] = ["document", "redacted-view", "evidence"];

/// Whether `args` are the library grammar's: a bare invocation, any library
/// anchor flag, a library-only command, a shared command named positionally,
/// or an unknown command that names no `--proof` (the library suggests the
/// closest one).
pub fn handles(args: &[OsString]) -> bool {
    let Some(first) = args.first() else {
        return true;
    };
    let first = first.to_str();
    if args.len() == 1 && matches!(first, Some("--help" | "-h" | "help")) {
        return false;
    }
    if first.is_some_and(|f| RAW_ONLY_COMMANDS.contains(&f)) {
        return false;
    }
    let has = |flag: &str| args.iter().any(|a| a == flag);
    if has("--key") || has("--unsigned-checkpoint") || has("--hex") {
        return true;
    }
    match first {
        Some(f) if LIBRARY_COMMANDS.contains(&f) => true,
        // A shared command is the library's only when it names its proof
        // positionally; `--proof` marks the raw grammar, and anything else
        // (including a raw-grammar usage error) is the raw parser's to judge.
        Some(f) if SHARED_COMMANDS.contains(&f) => !has("--proof") && has_positional(&args[1..]),
        // An unknown command naming `--proof` is a raw-grammar mistake and
        // gets the raw parser's error event; otherwise the library suggests
        // the closest command.
        Some(f) => !f.starts_with("--") && !has("--proof"),
        None => false,
    }
}

/// Flags of either grammar that take a value.
const VALUE_FLAGS: [&str; 24] = [
    "--state",
    "--after-seq",
    "--through-seq",
    "--reader",
    "--witness",
    "--quorum",
    "--proof",
    "--checkpoint",
    "--next-checkpoint",
    "--trusted",
    "--claimed",
    "--key",
    "--account",
    "--from",
    "--to",
    "--prefix",
    "--kind",
    "--expect",
    "--receipt",
    "--expect-account",
    "--expect-unit",
    "--expect-through",
    "--expect-debits",
    "--expect-credits",
];

/// Whether `rest` (the arguments after the command) holds an argument that
/// is neither a flag nor a flag's value.
fn has_positional(rest: &[OsString]) -> bool {
    let mut skip_value = false;
    for argument in rest {
        if skip_value {
            skip_value = false;
            continue;
        }
        match argument.to_str() {
            Some(flag) if flag.starts_with("--") => {
                skip_value = !flag.contains('=') && VALUE_FLAGS.contains(&flag);
            }
            _ => return true,
        }
    }
    false
}

/// The library's usage text, appended to this binary's `--help`.
#[must_use]
pub fn usage() -> String {
    format!("{}\n{}", fa_verify::cli::USAGE, witness::HELP)
}

fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let too_large = || {
        std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("input exceeds the {MAX_INPUT_BYTES}-byte bound"),
        )
    };
    if file.metadata()?.len() > MAX_INPUT_BYTES as u64 {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    // The second bound also covers a file that grew after its metadata was read.
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}

/// Run the library CLI over `args`, printing its report and exiting with its
/// code (5 when stdout cannot be written).
pub fn run(args: Vec<OsString>) -> ExitCode {
    if args.first().is_some_and(|arg| arg == "witness") {
        return emit(witness::run(&args));
    }
    if args.is_empty() {
        return emit(fa_verify::cli::Output {
            exit: 0,
            stdout: format!("{}\n", usage()),
            stderr: String::new(),
        });
    }
    let mut raw: Vec<OsString> = Vec::new();
    let args: Vec<String> = args
        .into_iter()
        .map(|argument| {
            argument.into_string().unwrap_or_else(|argument| {
                raw.push(argument);
                format!("{PLACEHOLDER}{}", raw.len() - 1)
            })
        })
        .collect();
    let read = |path: &str| {
        let original = path
            .strip_prefix(PLACEHOLDER)
            .and_then(|index| index.parse::<usize>().ok())
            .and_then(|index| raw.get(index));
        let os: &OsStr = original.map_or_else(|| OsStr::new(path), OsString::as_os_str);
        read_bounded(Path::new(os))
    };
    emit(fa_verify::cli::run(&args, &read))
}

fn emit(out: fa_verify::cli::Output) -> ExitCode {
    let written = {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(out.stdout.as_bytes())
            .and_then(|()| stdout.flush())
    };
    let _ = std::io::stderr().lock().write_all(out.stderr.as_bytes());
    if let Err(error) = written {
        let _ = writeln!(std::io::stderr().lock(), "fa-verify: stdout: {error}");
        return ExitCode::from(5);
    }
    ExitCode::from(u8::try_from(out.exit).unwrap_or(EXIT_IO as u8))
}
