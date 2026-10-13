//! `fa-verify`, the dependency-free verifier as a command (plan §13.3).
//! Everything is in [`fa_verify::cli`]; this only reads files and exits.
//!
//! Inputs are read with a size bound checked before any allocation
//! ([`fa_verify::cli::MAX_INPUT_BYTES`]), and a file name that is not UTF-8
//! stays usable: such an argument is passed to the CLI under a NUL-prefixed
//! placeholder (a real path never contains NUL) and resolved back to the
//! original name when the file is opened.

#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use fa_verify::cli::{EXIT_IO, MAX_INPUT_BYTES};

const PLACEHOLDER: &str = "\u{0}non-UTF-8 argument #";

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

fn main() -> ExitCode {
    let mut raw: Vec<OsString> = Vec::new();
    let args: Vec<String> = std::env::args_os()
        .skip(1)
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
        return ExitCode::from(EXIT_IO as u8);
    }
    ExitCode::from(u8::try_from(out.exit).unwrap_or(EXIT_IO as u8))
}
