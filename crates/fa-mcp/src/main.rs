//! `fa-mcp` — the FrankenAccounting MCP server over stdio (bead fa-xex):
//!
//! `fa-mcp --book <dir> [--keys <file>] [--principal <name>]
//! [--profile agent|preparer] [--grant <op>]...` serves the verb registry's tool
//! clusters and resources on stdin/stdout (newline-delimited JSON-RPC, the
//! MCP stdio transport) until the host closes stdin. `--book` (or `FA_BOOK`)
//! fixes the book for this session. Identity and operations are trusted
//! launch configuration, never tool arguments. Calls retain their typed
//! capability and refuse daemon forwarding until session binding is available.
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

const USAGE: &str = "fa-mcp — the FrankenAccounting MCP server (stdio)\n\nusage\n  fa-mcp --book <dir> [--keys <file>] [--files <dir>] [--principal <name>]\n         [--profile agent|preparer] [--grant <op>]...\n  fa-mcp --book <dir> [--keys <file>] [--files <dir>] --token <file>\n  (either form) [--cluster <on-demand cluster>]...   e.g. --cluster fa.draft\n  fa-mcp --help\n  fa-mcp --version\n\nFA_BOOK may supply the launch book. The default principal is mcp-agent and the\ndefault profile is agent. Default operations are read, post, verify; an explicit\n--grant list narrows the session to the named operations within its profile.\nIdentity, profile, operations, book, keys and optional --files containment root\nare fixed at launch. Tool arguments cannot override them or confirm dangerous\noperations. Agent writes to trunk are refused by the kernel; drafts remain\npending (fa-s7x). Launch configuration is trusted operator input, not\nauthenticated issuance (fa-v62/fa-r3q). A running fad causes a lease refusal\nuntil it can preserve this session's authority.\n";

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
