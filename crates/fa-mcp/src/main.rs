//! `fa-mcp` — the FrankenAccounting MCP server over stdio (bead fa-xex):
//!
//! `fa-mcp [--book <dir>] [--keys <file>]` serves the verb registry's tool
//! clusters and resources on stdin/stdout (newline-delimited JSON-RPC, the
//! MCP stdio transport) until the host closes stdin. `--book` (or `FA_BOOK`)
//! names the book every call runs against unless the call names its own.
//! Each call runs exactly as `fa` would: directly under the book's writer
//! lease, or through the `fad` that holds it.
//!
//! stdout is the transport; diagnostics go to stderr. Exit codes follow the
//! `fa` dictionary: 2 usage, 5 foundation (the registry or the server could
//! not be built); the transport's own end is 0.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;
use fa_mcp::server::{ServerConfig, build_server};

const USAGE: &str = "fa-mcp — the FrankenAccounting MCP server (stdio)\n\nusage\n  fa-mcp [--book <dir>] [--keys <file>]   (serves until stdin closes; FA_BOOK names the default book)\n  fa-mcp --help\n  fa-mcp --version\n";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
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
            "--book" | "--keys" => {
                let Some(value) = argv.get(i + 1) else {
                    eprintln!(
                        "usage: {} needs a value\n  fix: {} <path>",
                        argv[i], argv[i]
                    );
                    return ExitCode::from(2);
                };
                if argv[i] == "--book" {
                    config.book = Some(PathBuf::from(value));
                } else {
                    config.keys = Some(PathBuf::from(value));
                }
                i += 2;
            }
            other => {
                let (flag, value) = other.split_once('=').unwrap_or((other, ""));
                match flag {
                    "--book" if !value.is_empty() => config.book = Some(PathBuf::from(value)),
                    "--keys" if !value.is_empty() => config.keys = Some(PathBuf::from(value)),
                    _ => {
                        eprintln!(
                            "usage: unknown argument `{other}`\n  fix: fa-mcp [--book <dir>] [--keys <file>]"
                        );
                        return ExitCode::from(2);
                    }
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
    let server = match build_server(config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error (exit 5): {e}");
            return ExitCode::from(5);
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
