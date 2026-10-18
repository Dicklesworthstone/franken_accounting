//! The `fa` front door: run a command directly under the book's writer
//! lease, or through the `fad` daemon that holds it (plan §5.10, §15.3).
//!
//! - `fa book create` validates every argument before anything is written;
//!   only then does its handler create the directory and take the writer
//!   lease, and key creation and genesis run under that same lease. A refused
//!   create leaves no directory, lease note or key.
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

use std::io::Write;

use crate::args;
use crate::authority::{CapabilityToken, LaunchAuthority};
use crate::cli::{self, Books, Captured, Files};
use crate::client::{self, ClientError};
use crate::lease::{Lease, LeaseError};
use crate::verbs;

mod routing;

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
    if parsed.flag("--token").is_some() {
        return fa_with_token(argv, &parsed, files, capture);
    }
    if discovery(&parsed, reg) {
        return cli::run(argv, Books::Dir, files, capture);
    }
    // The lease, the socket and the forwarded command all name the book the
    // command will open: its path in the caller's working directory.
    let Some(dir) = cli::named_book(&parsed, files.cwd.as_deref()) else {
        return cli::run(argv, Books::Dir, files, capture);
    };
    if via == Some("fad") {
        return through_daemon(argv, &parsed, &dir, None, None, &files, capture);
    }
    let words = command_words(&parsed, reg);
    let note = format!("fa pid={}", std::process::id());
    if words == ["book", "create"] || words == ["demo", "init"] {
        if !dir.exists() {
            let books = Books::LeasedOnOpen {
                lease: reg.daemon.lease.clone(),
                note,
                held: None,
            };
            return cli::run(argv, books, files, capture);
        }
        if !Lease::is_book_dir(&dir) && !Lease::is_empty_or_lease_only(&dir, &reg.daemon.lease) {
            return cli::environment_error(
                argv,
                format!(
                    "cannot prepare book directory {} for its writer lease: directory is not a book and is not empty",
                    dir.display()
                ),
                capture,
            );
        }
        if !Lease::is_book_dir(&dir) {
            // Genesis: the handler validates every argument, then prepares
            // the directory and takes this same writer lease before any key
            // or store byte (`Books::lease_for_genesis`).
            let books = Books::LeasedOnOpen {
                lease: reg.daemon.lease.clone(),
                note,
                held: None,
            };
            return cli::run(argv, books, files, capture);
        }
    } else if !Lease::is_book_dir(&dir) {
        let books = Books::LeasedOnOpen {
            lease: reg.daemon.lease.clone(),
            note,
            held: None,
        };
        return cli::run(argv, books, files, capture);
    } else if Lease::holder(&dir, &reg.daemon.lease).is_none()
        && let Err(error @ fa::book::BookError::KeyFilePermissions { .. }) =
            fa::book::BookKeys::check_permissions(&cli::keys_path(
                &parsed,
                &dir,
                files.cwd.as_deref(),
            ))
    {
        if words == ["doctor"] {
            let books = Books::LeasedOnOpen {
                lease: reg.daemon.lease.clone(),
                note,
                held: None,
            };
            return cli::run(argv, books, files, capture);
        }
        return cli::book_error(argv, error, capture);
    }
    match Lease::acquire(&dir, &reg.daemon.lease, &note) {
        Ok(lease) => {
            let result = cli::run(argv, Books::Dir, files, capture);
            drop(lease);
            result
        }
        Err(LeaseError::Io { ref error, .. })
            if error.kind() == std::io::ErrorKind::NotFound && !dir.exists() =>
        {
            let books = Books::LeasedOnOpen {
                lease: reg.daemon.lease.clone(),
                note,
                held: None,
            };
            cli::run(argv, books, files, capture)
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
                through_daemon(argv, &parsed, &dir, Some(held), None, &files, capture)
            }
        }
    }
}

/// `fa --token <file>` (plan §14.2, bead fa-r3q): act as the holder of an
/// issued capability token instead of the embedded owner. The token fixes
/// the principal and its journaled capability, so `--as` and `--grant` are
/// refused beside it; the session then runs exactly as a token-bound MCP
/// session does, directly under the writer lease or through the book's fad.
fn fa_with_token(
    argv: &[String],
    parsed: &args::Args,
    files: Files,
    capture: bool,
) -> (u8, Captured) {
    const FIX: &str = "fa --token <file> --book <dir> <command>   (the token names the principal; drop --as and --grant)";
    for flag in ["--as", "--grant"] {
        if parsed.flag(flag).is_some() {
            return cli::usage_error(
                argv,
                format!(
                    "{flag} cannot be combined with --token: the token fixes the principal and its operations"
                ),
                FIX,
                capture,
            );
        }
    }
    let path = parsed.flag("--token").unwrap_or_default();
    if path.is_empty() || path == "-" || parsed.flag_all("--token").len() > 1 {
        return cli::usage_error(argv, "--token names one holder's token file", FIX, capture);
    }
    let bytes = match std::fs::read(files.resolve(path)) {
        Ok(bytes) => bytes,
        Err(e) => {
            return cli::usage_error(
                argv,
                format!("--token {path}: cannot read the token file: {e}"),
                FIX,
                capture,
            );
        }
    };
    let token = match CapabilityToken::decode(&bytes) {
        Ok(token) => token,
        Err(e) => return cli::usage_error(argv, format!("--token {path}: {e}"), FIX, capture),
    };
    let Some(dir) = cli::named_book(parsed, files.cwd.as_deref()) else {
        return cli::usage_error(
            argv,
            "--token needs --book <dir> (or FA_BOOK)",
            FIX,
            capture,
        );
    };
    let keys = parsed
        .flag("--keys")
        .map(|_| cli::keys_path(parsed, &dir, files.cwd.as_deref()));
    let authority = match LaunchAuthority::from_token(dir, keys, &token) {
        Ok(authority) => authority,
        Err(message) => {
            return cli::refuse(
                argv,
                fa_journal::Refusal::new(
                    fa_journal::refusal::code::CAPABILITY,
                    fa_journal::exit::SAFETY,
                    message,
                    "plan §14.2–§14.4 (a token-bound session stays within its launch template)",
                    "ask the issuer for a token within the agent or preparer ceiling",
                ),
                capture,
            );
        }
    };
    fa_with_authority(&routing::bound_args(parsed), files, &authority, capture)
}

/// Run a request under the authority fixed when an MCP server starts, or by
/// `fa --token`.
///
/// The capability is an in-process value, never a command-line argument or
/// an unauthenticated daemon frame. Discovery needs no book; every command
/// that may observe the book must take its configured writer lease. When
/// the book's fad holds the lease, a token-bound session presents its token
/// to the daemon, which binds the request to it (fa-r3q); a launch-config
/// session, which has no token to present, is refused.
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
        "--token",
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
    if let Some(token) = authority.token()
        && let Some(holder) = Lease::holder(authority.book(), &reg.daemon.lease)
    {
        let held = LeaseError::Held {
            path: authority.book().join(&reg.daemon.lease),
            holder,
        };
        return through_daemon(
            argv,
            &parsed,
            authority.book(),
            Some(held),
            Some(token),
            &files,
            capture,
        );
    }
    let note = format!(
        "fa-mcp pid={} principal={}",
        std::process::id(),
        authority.principal()
    );
    // The writer lease is taken when the handler opens the book, after the
    // command's authority admission: a refused call never touches the book.
    let books = Books::LeasedOnOpen {
        lease: reg.daemon.lease.clone(),
        note,
        held: None,
    };
    cli::run_with_authority(argv, books, files, authority, capture)
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
    let words = command_words(parsed, reg);
    parsed.switch("--help")
        || parsed.switch("--version")
        || matches!(
            words.as_slice(),
            [] | ["help" | "capabilities" | "robot-docs", ..] | ["chart", "templates", ..]
        )
}

fn through_daemon(
    argv: &[String],
    parsed: &args::Args,
    dir: &std::path::Path,
    held: Option<LeaseError>,
    token: Option<&CapabilityToken>,
    files: &Files,
    capture: bool,
) -> (u8, Captured) {
    let Ok(reg) = verbs::registry() else {
        return cli::run(argv, Books::Dir, files.clone(), capture);
    };
    let token = match token.map(CapabilityToken::canonical_bytes).transpose() {
        Ok(token) => token,
        Err(e) => return cli::foundation_error(argv, format!("capability token: {e}"), capture),
    };
    let request = match routing::request(parsed, dir, files, &reg.daemon, token) {
        Ok(request) => request,
        Err(routing::Error::Usage(message)) => {
            return cli::usage_error(
                argv,
                message,
                "pass the unchanged plan or intent through a readable input file, or reduce the complete request size",
                capture,
            );
        }
        Err(routing::Error::Environment(message)) => {
            return cli::environment_error(argv, message, capture);
        }
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
        let reg = verbs::registry().unwrap();
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
        let parsed = args::parse(&argv, &reg.value_flags(), &reg.switches()).unwrap();
        let request = routing::request(
            &parsed,
            std::path::Path::new("/abs/book"),
            &Files {
                cwd: Some("/client".into()),
                stdin: crate::cli::Stdin::Missing,
            },
            &reg.daemon,
        )
        .unwrap();
        let out = args::parse(&request.argv, &reg.value_flags(), &reg.switches()).unwrap();
        assert_eq!(out.positional, vec!["tb"]);
        assert_eq!(out.flag_all("--via"), Vec::<&str>::new());
        assert_eq!(out.flag_all("--book"), vec!["/abs/book"]);
        assert_eq!(out.flag_all("--period"), vec!["P"]);
        assert_eq!(out.switches, vec!["--json"]);
        assert_eq!(out.flags.len(), 2);
        assert_eq!(request.cwd.as_deref(), Some("/client"));
    }
}
