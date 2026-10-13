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

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use fa_verify::cli::{EXIT_IO, MAX_INPUT_BYTES};

const PLACEHOLDER: &str = "\u{0}non-UTF-8 argument #";

/// Commands only the library verifies.
const LIBRARY_COMMANDS: [&str; 5] = ["state", "checkpoint", "scope", "doc-commit", "bundle"];
/// Commands both grammars verify; the raw grammar always names `--proof`.
const SHARED_COMMANDS: [&str; 4] = ["inclusion", "prefix", "balance", "consistency"];
/// Commands only this binary's own parser verifies.
const RAW_ONLY_COMMANDS: [&str; 2] = ["document", "redacted-view"];

/// Whether `args` are the library grammar's: a bare invocation, any library
/// anchor flag, a library-only command, a shared command named positionally,
/// or an unknown command (the library suggests the closest one).
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
        Some(f) if SHARED_COMMANDS.contains(&f) => !has("--proof"),
        Some(f) => !f.starts_with("--"),
        None => false,
    }
}

/// The library's usage text, appended to this binary's `--help`.
#[must_use]
pub fn usage() -> &'static str {
    fa_verify::cli::USAGE
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
    let out = fa_verify::cli::run(&args, &read);
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
