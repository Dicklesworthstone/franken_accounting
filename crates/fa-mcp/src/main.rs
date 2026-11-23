//! `fa-mcp` — the FrankenAccounting MCP server over stdio (bead fa-xex):
//!
//! `fa-mcp --book <dir> [--keys <file>] [--principal <name>]
//! [--profile agent|preparer] [--grant <op>]...` serves the verb registry's tool
//! clusters and resources on stdin/stdout (newline-delimited JSON-RPC, the
//! MCP stdio transport) until the host closes stdin. `--book` (or `FA_BOOK`)
//! fixes the book for this session. Identity and operations are trusted
//! launch configuration, never tool arguments. A holder token also binds
//! requests sent to the book's running daemon.
//!
//! stdout is the transport; diagnostics go to stderr. Exit codes follow the
//! `fa` dictionary: 2 usage, 5 foundation (the registry or the server could
//! not be built, or a panic, reported as FA-REF-153 on stderr); the
//! transport's own end is 0.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;
use fa_cli::authority::LaunchProfile;
use fa_mcp::server::{ServerConfig, build_server};

const USAGE: &str = "fa-mcp — the FrankenAccounting MCP server (stdio)

usage
  fa-mcp --book <dir> [--keys <file>] [--files <dir>] [--principal <name>]
         [--profile agent|preparer] [--grant <op>]...
  fa-mcp --book <dir> [--keys <file>] [--files <dir>] --token <file>
  (either form) [--cluster <on-demand cluster|all>]...
  fa-mcp --help
  fa-mcp --version

FA_BOOK may supply the book. FA_TOKEN may supply the holder token with the
default launch identity. The default principal is mcp-agent and the default
profile is agent. Default operations are read, post and verify. An explicit
--grant list selects the session's operations within its profile. The book,
keys, identity, operations and optional --files root are fixed at launch.
Tool arguments cannot override them or confirm dangerous operations.

Start with --cluster fa.draft to create a draft with fa_draft_manage and plan
entries into it with fa_post_post. Agent sessions cannot post to trunk. A
different Human principal with approval authority promotes an ordinary draft
on the host with `fa draft promote <name> --as <approver> --yes`.

An issued token binds each request to its holder. When fad holds the book's
writer lease, a token-bound session routes through <dir>/fad.sock. To host
stdio on the daemon, run `fad serve --book <dir> --mcp stdio --token <file>`.
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // Never silent on a panic (fa-y9z): stdout is the transport, so the
    // FA-REF-153 refusal goes to stderr with exit 5, never Rust's 101.
    fa_cli::panic::install("fa-mcp");
    match fa_cli::panic::catch(|| {
        // Debug builds only: the never-silent-fail test's deliberate panic.
        #[cfg(debug_assertions)]
        if std::env::var_os("FA_TEST_PANIC").is_some() {
            std::panic::panic_any(
                "FA_TEST_PANIC: a deliberate panic for the never-silent-fail test",
            );
        }
        serve(&argv)
    }) {
        Ok(code) => code,
        Err(text) => {
            eprintln!("error (exit 5): {}", fa_cli::panic::refusal(&text));
            ExitCode::from(5)
        }
    }
}

fn serve(argv: &[String]) -> ExitCode {
    let mut config = ServerConfig::default();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--version" => {
                println!("fa-mcp {}", fa_mcp::VERSION);
                return ExitCode::SUCCESS;
            }
            "--book" | "--keys" | "--files" | "--principal" | "--profile" | "--grant"
            | "--token" | "--cluster" => {
                let Some(value) = argv.get(i + 1) else {
                    eprintln!(
                        "usage: {} needs a value\n  fix: {} <value>",
                        argv[i], argv[i]
                    );
                    return ExitCode::from(2);
                };
                if let Err(e) = set_option(&mut config, &argv[i], value) {
                    eprintln!("usage: {e}\n  fix: fa-mcp --help");
                    return ExitCode::from(2);
                }
                i += 2;
            }
            other => {
                let (flag, value) = other.split_once('=').unwrap_or((other, ""));
                if value.is_empty() || set_option(&mut config, flag, value).is_err() {
                    eprintln!("usage: invalid argument `{other}`\n  fix: fa-mcp --help");
                    return ExitCode::from(2);
                }
                i += 1;
            }
        }
    }
    if config.book.is_none()
        && let Ok(dir) = std::env::var("FA_BOOK")
        && !dir.is_empty()
    {
        config.book = Some(PathBuf::from(dir));
    }
    if config.token.is_none()
        && config.principal == "mcp-agent"
        && config.profile == LaunchProfile::Agent
        && config.grants.is_empty()
        && let Ok(token_file) = std::env::var("FA_TOKEN")
        && !token_file.is_empty()
        && let Err(e) = set_option(&mut config, "--token", &token_file)
    {
        eprintln!("usage: {e}\n  fix: fa-mcp --help");
        return ExitCode::from(2);
    }
    if config.book.is_none() {
        eprintln!(
            "usage: a launch book is required\n  fix: fa-mcp --book <dir> (or set FA_BOOK before launch)"
        );
        return ExitCode::from(2);
    }
    let server = match build_server(config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error (exit {}): {e}", e.exit());
            return ExitCode::from(e.exit());
        }
    };
    let reactor = match create_reactor() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error (exit 5): stdio reactor: {e:?}");
            return ExitCode::from(5);
        }
    };
    let runtime = match RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .blocking_threads(0, 16)
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error (exit 5): runtime: {e:?}");
            return ExitCode::from(5);
        }
    };
    runtime.block_on(async move {
        let Some(cx) = Cx::current() else {
            eprintln!("error (exit 5): no application context on the runtime");
            return ExitCode::from(5);
        };
        // Serves until stdin closes, then exits the process itself.
        server.run_stdio_with_cx(&cx).await
    })
}

fn set_option(config: &mut ServerConfig, flag: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{flag} needs a nonempty value"));
    }
    match flag {
        "--book" => config.book = Some(PathBuf::from(value)),
        "--keys" => config.keys = Some(PathBuf::from(value)),
        "--files" => config.files = Some(PathBuf::from(value)),
        "--principal" => config.principal = value.to_string(),
        "--profile" => {
            config.profile = LaunchProfile::from_name(value)
                .ok_or_else(|| format!("unknown profile `{value}`; use agent or preparer"))?;
        }
        "--grant" => config.grants.push(value.to_string()),
        "--cluster" => config.clusters.push(value.to_string()),
        "--token" => {
            let bytes = std::fs::read(value)
                .map_err(|e| format!("--token {value}: cannot read the token file: {e}"))?;
            let token = fa_cli::authority::CapabilityToken::decode(&bytes)
                .map_err(|e| format!("--token {value}: {e}"))?;
            config.token = Some(token);
        }
        _ => return Err(format!("unknown launch flag `{flag}`")),
    }
    Ok(())
}
