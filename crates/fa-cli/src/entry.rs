//! The `fa` front door: run a command directly under the book's writer
//! lease, or through the `fad` daemon that holds it (plan §5.10, §15.3).
//!
//! - No book directory (`--book`/`FA_BOOK`) named, or the directory does not
//!   exist yet (`fa book create`): run directly; there is no lease to take.
//! - The lease is free: take it, run directly, release it. Every direct
//!   command is the book's one writer for its duration.
//! - The lease is held: send the command line to the book's daemon and
//!   replay its stdout, stderr and exit code verbatim. If nothing answers on
//!   the socket (another direct `fa` holds the lease), refuse FA-REF-018,
//!   exit 6.
//!
//! `--via fad` insists on the daemon (exit 4 when none serves the book);
//! `--via direct` refuses (FA-REF-018) instead of routing when the lease is
//! held.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use crate::args;
use crate::cli::{self, Books, Captured, Files, Stdin};
use crate::client::{self, ClientError};
use crate::lease::{Lease, LeaseError};
use crate::verbs;
use crate::wire::{Op, Request};

/// Run one `fa` command line. With `capture`, the output is returned instead
/// of written to stdio.
pub fn fa(argv: &[String], capture: bool) -> (u8, Captured) {
    fa_with(argv, Files::default(), capture)
}

/// [`fa`] with the files and stdin the command's arguments resolve against
/// (`fa_cli::cli::Files`): a host that is not the `fa` binary (fa-mcp) hands
/// a forwarded stdin here instead of the process's own, so `-` never reads
/// the host's transport. Through a daemon, the forwarded bytes travel in the
/// request.
pub fn fa_with(argv: &[String], files: Files, capture: bool) -> (u8, Captured) {
    let Ok(reg) = verbs::registry() else {
        // `cli::run` reports the unreadable registry itself.
        return cli::run(argv, Books::Dir, files, capture);
    };
    let Ok(parsed) = args::parse(argv, &reg.value_flags(), &reg.switches()) else {
        return cli::run(argv, Books::Dir, files, capture);
    };
    let via = parsed.flag("--via");
    if let Some(other) = via.filter(|v| *v != "fad" && *v != "direct") {
        return cli::usage_error(
            argv,
            format!("--via `{other}` is not a transport"),
            "--via fad (through the book's daemon) or --via direct (open the book here)",
            capture,
        );
    }
    let dir = parsed.flag("--book").map(PathBuf::from).or_else(|| {
        std::env::var("FA_BOOK")
            .ok()
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
    });
    let Some(dir) = dir else {
        return cli::run(argv, Books::Dir, files, capture);
    };
    if via == Some("fad") {
        return through_daemon(argv, &dir, None, &files, capture);
    }
    let note = format!("fa pid={}", std::process::id());
    match Lease::acquire(&dir, &reg.daemon.lease, &note) {
        Ok(lease) => {
            let result = cli::run(argv, Books::Dir, files, capture);
            drop(lease);
            result
        }
        // The directory does not exist (yet): nothing to lease or serve.
        Err(LeaseError::Io { .. }) => cli::run(argv, Books::Dir, files, capture),
        Err(held @ LeaseError::Held { .. }) => {
            if via == Some("direct") {
                cli::refuse(argv, held.refusal(&dir), capture)
            } else {
                through_daemon(argv, &dir, Some(held), &files, capture)
            }
        }
    }
}

/// The command line as the daemon should run it: without `--via`, and with
/// the book named by its absolute path (the daemon's working directory is
/// not the client's).
fn for_daemon(argv: &[String], dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len() + 2);
    let mut skip = false;
    for a in argv {
        if skip {
            skip = false;
            continue;
        }
        if a == "--via" || a == "--book" {
            skip = true;
            continue;
        }
        if a.starts_with("--via=") || a.starts_with("--book=") {
            continue;
        }
        out.push(a.clone());
    }
    let absolute = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    out.push("--book".into());
    out.push(absolute.display().to_string());
    out
}

fn through_daemon(
    argv: &[String],
    dir: &std::path::Path,
    held: Option<LeaseError>,
    files: &Files,
    capture: bool,
) -> (u8, Captured) {
    let Ok(reg) = verbs::registry() else {
        return cli::run(argv, Books::Dir, files.clone(), capture);
    };
    let forwarded = for_daemon(argv, dir);
    // stdin travels only when an argument asks for it: the host's forwarded
    // bytes, or this process's stdin when something is piped to it. A host
    // that forwarded none (Missing) sends none, and the daemon refuses `-`.
    let wants_stdin = forwarded.iter().any(|a| a == "-");
    let stdin = match &files.stdin {
        Stdin::Forwarded(bytes) if wants_stdin => Some(bytes.clone()),
        Stdin::Process if wants_stdin && !std::io::stdin().is_terminal() => {
            let mut bytes = Vec::new();
            if let Err(e) = std::io::stdin().read_to_end(&mut bytes) {
                return cli::usage_error(
                    argv,
                    format!("stdin: {e}"),
                    "pipe the document to stdin",
                    capture,
                );
            }
            Some(bytes)
        }
        _ => None,
    };
    let request = Request {
        op: Op::Run,
        argv: forwarded,
        cwd: files
            .cwd
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .map(|d| d.display().to_string()),
        stdin,
    };
    let socket = dir.join(&reg.daemon.socket);
    match client::call(&socket, &request, &reg.daemon) {
        Ok(response) => {
            if capture {
                (
                    response.exit,
                    Captured {
                        stdout: response.stdout,
                        stderr: response.stderr,
                    },
                )
            } else {
                let _ = std::io::stdout().write_all(response.stdout.as_bytes());
                let _ = std::io::stdout().flush();
                let _ = std::io::stderr().write_all(response.stderr.as_bytes());
                (response.exit, Captured::default())
            }
        }
        Err(ClientError::Connect(e)) => match held {
            Some(held) => cli::refuse(argv, held.refusal(dir), capture),
            None => cli::environment_error(
                argv,
                format!(
                    "no fad serves {} ({}: {e})",
                    dir.display(),
                    socket.display()
                ),
                capture,
            ),
        },
        Err(e) => cli::foundation_error(argv, format!("fad transport: {e}"), capture),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forwarded_command_line_drops_via_and_names_the_book_absolutely() {
        let argv: Vec<String> = [
            "tb",
            "--via",
            "fad",
            "--book",
            "rel",
            "--period",
            "P",
            "--via=fad",
            "--json",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let out = for_daemon(&argv, std::path::Path::new("/abs/book"));
        assert_eq!(
            out,
            vec!["tb", "--period", "P", "--json", "--book", "/abs/book"]
        );
    }
}
