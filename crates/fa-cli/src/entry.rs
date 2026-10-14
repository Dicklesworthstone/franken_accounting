//! The `fa` front door: run a command directly under the book's writer
//! lease, or through the `fad` daemon that holds it (plan §5.10, §15.3).
//!
//! - A new book directory is created before taking its writer lease. Genesis,
//!   key creation and ordinary commands all run under that same lease.
//! - Lease I/O failures refuse execution; they never authorize an unlocked
//!   book open. Only book-independent discovery may run without a lease.
//! - The lease is free: take it, run directly, release it. Every direct
//!   command is the book's one writer for its duration.
//! - The lease is held: send the command line to the book's daemon and
//!   replay its stdout, stderr and exit code verbatim. If nothing answers on
//!   the socket (another direct `fa` holds the lease), refuse FA-REF-018,
//!   exit 6.
//!
//! `--via fad` insists on the daemon (exit 4 when none serves the book);
//! `--via direct` refuses (FA-REF-018) instead of routing when the lease is
//! held. These are the embedded-owner entry points. An MCP host must use
//! [`fa_with_authority`], which keeps its launch capability and never routes
//! through the unauthenticated daemon protocol.

use std::io::{IsTerminal, Read, Write};

use crate::args;
use crate::authority::LaunchAuthority;
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
/// (`fa_cli::cli::Files`): a trusted embedded-owner host hands a forwarded
/// stdin here instead of the process's own. Through a daemon, the forwarded
/// bytes travel in the request. MCP hosts use [`fa_with_authority`] instead.
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
    // The lease, the socket and the forwarded command all name the book the
    // command will open: its path in the caller's working directory.
    let Some(dir) = cli::named_book(&parsed, files.cwd.as_deref()) else {
        return cli::run(argv, Books::Dir, files, capture);
    };
    if via == Some("fad") {
        return through_daemon(argv, &dir, None, &files, capture);
    }
    // Genesis is a write too. Create only the directory here, then compete
    // for the same lease as every later writer BEFORE the dispatcher creates
    // keys or opens the substrate. A failed command may leave an empty
    // directory and lease note; neither is a committed book.
    if !discovery(&parsed, reg)
        && command_words(&parsed, reg) == ["book", "create"]
        && let Err(error) = std::fs::create_dir_all(&dir)
    {
        return cli::environment_error(
            argv,
            format!(
                "cannot prepare book directory {} for its writer lease: {error}",
                dir.display()
            ),
            capture,
        );
    }
    let note = format!("fa pid={}", std::process::id());
    match Lease::acquire(&dir, &reg.daemon.lease, &note) {
        Ok(lease) => {
            let result = cli::run(argv, Books::Dir, files, capture);
            drop(lease);
            result
        }
        // Help/discovery does not open a book. Every other operation must
        // fail closed, including NotFound, permission, lock and note errors.
        Err(LeaseError::Io { .. }) if discovery(&parsed, reg) => {
            cli::run(argv, Books::Dir, files, capture)
        }
        Err(error @ LeaseError::Io { .. }) => cli::environment_error(
            argv,
            format!("cannot acquire the book's writer lease: {error}"),
            capture,
        ),
        Err(held @ LeaseError::Held { .. }) => {
            if via == Some("direct") {
                cli::refuse(argv, held.refusal(&dir), capture)
            } else {
                through_daemon(argv, &dir, Some(held), &files, capture)
            }
        }
    }
}

/// Run a request under the authority fixed when an MCP server starts.
///
/// The capability is an in-process value, never a command-line argument or
/// an unauthenticated daemon frame. Discovery needs no book; every command
/// that may observe the book must take its configured writer lease. A held
/// lease is refused until the daemon can bind an authenticated session.
pub fn fa_with_authority(
    argv: &[String],
    files: Files,
    authority: &LaunchAuthority,
    capture: bool,
) -> (u8, Captured) {
    let Ok(reg) = verbs::registry() else {
        return cli::run_with_authority(argv, Books::Dir, files, authority, capture);
    };
    let Ok(parsed) = args::parse(argv, &reg.value_flags(), &reg.switches()) else {
        return cli::run_with_authority(argv, Books::Dir, files, authority, capture);
    };
    // Judge parsed arguments, not strings inside an ordinary value or after
    // `--`. The bound dispatcher repeats this check and binds book/keys in
    // Args itself, so no appended argv can turn a positional value into an
    // authority override.
    for flag in [
        "--as",
        "--grant",
        "--yes",
        "--book",
        "--keys",
        "--via",
        "--principal",
        "--profile",
    ] {
        if parsed.flag(flag).is_some() || parsed.switch(flag) {
            return cli::usage_error_with_authority(
                argv,
                format!("{flag} cannot be supplied by a launch-bound request"),
                "identity, permissions, book and keys are fixed when the server starts; ask the operator to start a server with the required authority",
                authority,
                capture,
            );
        }
    }
    if discovery(&parsed, reg) {
        return cli::run_with_authority(argv, Books::Dir, files, authority, capture);
    }
    let note = format!(
        "fa-mcp pid={} principal={}",
        std::process::id(),
        authority.principal()
    );
    match Lease::acquire(authority.book(), &reg.daemon.lease, &note) {
        Ok(lease) => {
            let result = cli::run_with_authority(argv, Books::Dir, files, authority, capture);
            drop(lease);
            result
        }
        Err(held @ LeaseError::Held { .. }) => {
            let mut refusal = held.refusal(authority.book());
            refusal.message.push_str(
                "; launch-bound authority cannot be forwarded through the unauthenticated fad protocol",
            );
            refusal.fix = "ask the operator to release the book's writer lease, then retry this launch-bound session; authenticated daemon sessions are not yet available (fa-r3q)".into();
            cli::refuse_with_authority(argv, refusal, authority, capture)
        }
        Err(error @ LeaseError::Io { .. }) => cli::environment_error_with_authority(
            argv,
            format!("cannot acquire the configured book's writer lease: {error}"),
            authority,
            capture,
        ),
    }
}

/// Interpret registered aliases as the dispatcher does. Flag-looking values
/// and words after `--` remain data; never infer discovery from raw argv.
fn command_words<'a>(parsed: &'a args::Args, reg: &'a verbs::Registry) -> Vec<&'a str> {
    match parsed.positional.first().and_then(|word| reg.alias(word)) {
        Some(alias) => alias
            .expands
            .iter()
            .chain(parsed.positional.iter().skip(1))
            .map(String::as_str)
            .collect(),
        None => parsed.positional.iter().map(String::as_str).collect(),
    }
}

fn discovery(parsed: &args::Args, reg: &verbs::Registry) -> bool {
    parsed.switch("--help")
        || parsed.switch("--version")
        || matches!(
            command_words(parsed, reg).first().copied(),
            None | Some("help" | "capabilities" | "robot-docs")
        )
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
