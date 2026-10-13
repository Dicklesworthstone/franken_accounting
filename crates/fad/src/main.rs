//! `fad` — the FrankenAccounting daemon binary (bead fa-i8j):
//!
//! - `fad serve --book <dir> [--keys <file>] [--json]` takes the book's
//!   writer lease (a second daemon is refused, FA-REF-018, exit 6), opens the
//!   book, listens on `<dir>/fad.sock`, and answers `fa` until `fad stop`;
//! - `fad status --book <dir> [--json]` says whether a daemon serves the book;
//! - `fad stop --book <dir> [--json]` asks it to answer and exit, and returns
//!   once the lease is released.
//!
//! Names, limits, verbs and flags come from `registries/verbs.toml`
//! `[daemon]`; output follows the `fa` robot contract (stdout data, stderr
//! diagnostics, one event per line with --json, the exit-code dictionary).

#![forbid(unsafe_code)]

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use asupersync::Budget;
use asupersync::cx::ChildRegionSpec;
use asupersync::net::unix::UnixListener;
use asupersync::runtime::RuntimeBuilder;
use fa::book::{Book, BookKeys, Entropy};
use fa_cli::args::{self, Args, nearest};
use fa_cli::cli;
use fa_cli::client::{self, ClientError};
use fa_cli::json::{Json, obj, s};
use fa_cli::lease::{Lease, LeaseError};
use fa_cli::verbs::{self, Daemon};
use fa_cli::wire::{Op, Request};
use fad::{Limits, Server, line};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&argv))
}

fn run(argv: &[String]) -> u8 {
    let reg = match verbs::registry() {
        Ok(r) => r,
        Err(e) => {
            return cli::foundation_error(argv, format!("the embedded verb registry: {e}"), false)
                .0;
        }
    };
    let d = &reg.daemon;
    let flags: Vec<&str> = d.flags.iter().map(String::as_str).collect();
    let switches: Vec<&str> = d.switches.iter().map(String::as_str).collect();
    let parsed = match args::parse(argv, &flags, &switches) {
        Ok(a) => a,
        Err(e) => return cli::usage_error(argv, e.message, e.fix, false).0,
    };
    let verb = parsed.positional.first().map(String::as_str);
    if verb.is_none() || parsed.switch("--help") {
        let mut text = format!("{} — the FrankenAccounting daemon\n\nusage\n", d.binary);
        for u in &d.usage {
            text.push_str(&format!("  {u}\n"));
        }
        print!("{text}");
        return 0;
    }
    let Some(dir) = parsed.flag("--book").map(PathBuf::from).or_else(|| {
        std::env::var("FA_BOOK")
            .ok()
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
    }) else {
        return cli::usage_error(
            argv,
            "no book directory",
            "--book <dir> (or export FA_BOOK=<dir>)",
            false,
        )
        .0;
    };
    if parsed.switch("--bootstrap-system") && verb != Some("serve") {
        return cli::usage_error(
            argv,
            "--bootstrap-system is a local daemon launch authority choice",
            "fad serve --book <dir> --bootstrap-system (trusted-local book-key posture)",
            false,
        )
        .0;
    }
    match verb {
        Some("serve") => serve(argv, &parsed, d, &dir),
        Some("status") => status(argv, &parsed, d, &dir),
        Some("stop") => stop(argv, &parsed, d, &dir),
        Some(other) => {
            let known: Vec<&str> = d.verbs.iter().map(String::as_str).collect();
            cli::usage_error(
                argv,
                format!("unknown command `{other}`"),
                match nearest(other, &known) {
                    Some(n) => format!("did you mean `fad {n}`?"),
                    None => format!("fad {} --book <dir>", known.join("|")),
                },
                false,
            )
            .0
        }
        None => 0,
    }
}

fn serve(argv: &[String], parsed: &Args, d: &Daemon, dir: &Path) -> u8 {
    let json = parsed.switch("--json");
    let socket = dir.join(&d.socket);
    let note = format!("fad pid={} socket={}", std::process::id(), socket.display());
    let lease = match Lease::acquire(dir, &d.lease, &note) {
        Ok(l) => l,
        Err(e @ LeaseError::Held { .. }) => return cli::refuse(argv, e.refusal(dir), false).0,
        Err(e) => return cli::environment_error(argv, e.to_string(), false).0,
    };
    let keys_file = parsed
        .flag("--keys")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("book.keys"));
    let mut book = match BookKeys::load(&keys_file)
        .and_then(|keys| Book::open_dir(dir, keys, Entropy::production()))
    {
        Ok(b) => b,
        Err(e) => return cli::book_error(argv, e, false).0,
    };
    // Holding the lease proves no daemon serves this book, so a socket file
    // left by a crashed one is stale. Anything else at that path is not ours.
    if let Ok(meta) = std::fs::symlink_metadata(&socket) {
        if !meta.file_type().is_socket() {
            return cli::environment_error(
                argv,
                format!(
                    "refusing to replace {}: it is not a socket",
                    socket.display()
                ),
                false,
            )
            .0;
        }
        if let Err(e) = std::fs::remove_file(&socket) {
            return cli::environment_error(
                argv,
                format!("stale socket {}: {e}", socket.display()),
                false,
            )
            .0;
        }
    }
    let runtime = match RuntimeBuilder::new().build() {
        Ok(r) => r,
        Err(e) => return cli::foundation_error(argv, format!("runtime: {e:?}"), false).0,
    };
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let timed = if parsed.switch("--bootstrap-system") {
        let policy = match fad::timed::Policy::from_registry(d) {
            Ok(policy) => policy,
            Err(error) => return cli::foundation_error(argv, error.to_string(), false).0,
        };
        match fad::timed::TimedWork::bootstrap(&cx, &book, policy) {
            Ok(work) => Some(work),
            // An explicit request for timed work never silently falls back
            // to an unconfigured server if authority or time is absent.
            Err(error) => return cli::foundation_error(argv, error.to_string(), false).0,
        }
    } else {
        None
    };
    let limits = Limits::from_registry(d);
    let book_id = book.context().book_id.to_hex();
    let at = match book.head() {
        Ok(known_at) => cli::At {
            book: book_id.clone(),
            known_at,
            effective: "all".into(),
        },
        Err(e) => return cli::book_error(argv, e, false).0,
    };
    let result: Result<u64, String> = runtime.block_on(async {
        let region = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .map_err(|e| format!("region: {e:?}"))?;
        let listener = UnixListener::bind(&socket)
            .await
            .map_err(|e| format!("bind {}: {e}", socket.display()))?;
        let mut serving = vec![
            ("book_id", s(&book_id)),
            ("dir", s(dir.display().to_string())),
            ("socket", s(socket.display().to_string())),
            ("pid", Json::Int(i128::from(std::process::id()))),
            ("protocol", Json::Int(d.protocol)),
            (
                "max_frame_bytes",
                Json::Int(i128::try_from(d.max_frame_bytes).unwrap_or(i128::MAX)),
            ),
        ];
        serving.extend(fad::timed::status_fields(timed.as_ref()));
        let serving = obj(serving);
        print!(
            "{}",
            line(
                json,
                "fad_serving",
                serving,
                Some(&at),
                &format!(
                    "fad serving {} (book {book_id}) on {}; {}; stop with `fad stop --book {}`",
                    dir.display(),
                    socket.display(),
                    fad::timed::status_text(timed.as_ref()),
                    dir.display()
                ),
            )
        );
        let mut server = Server {
            book: &mut book,
            dir: dir.to_path_buf(),
            socket: socket.clone(),
            requests: 0,
            timed,
        };
        let served = fad::serve_book(region.cx(), &listener, limits, &mut server).await;
        // Dropping the listener removes the socket path it created.
        drop(listener);
        let requests = server.requests;
        region
            .close()
            .await
            .map_err(|e| format!("region close: {e:?}"))?;
        served.map_err(|e| format!("serve: {e}"))?;
        Ok(requests)
    });
    drop(book);
    drop(lease);
    match result {
        Ok(requests) => {
            let stopped = obj(vec![
                ("dir", s(dir.display().to_string())),
                ("requests", Json::Int(i128::from(requests))),
            ]);
            print!(
                "{}",
                line(
                    json,
                    "fad_stopped",
                    stopped,
                    None,
                    &format!(
                        "fad for {} stopped after {requests} requests; the writer lease is released",
                        dir.display()
                    ),
                )
            );
            0
        }
        Err(e) => cli::foundation_error(argv, e, false).0,
    }
}

fn request(op: Op, json: bool) -> Request {
    Request {
        op,
        argv: if json {
            vec!["--json".to_string()]
        } else {
            Vec::new()
        },
        cwd: None,
        stdin: None,
    }
}

fn not_serving(dir: &Path, socket: &Path, holder: Option<String>, json: bool) -> u8 {
    let mut fields = vec![
        ("serving", Json::Bool(false)),
        ("dir", s(dir.display().to_string())),
        ("socket", s(socket.display().to_string())),
        ("pid", Json::Null),
        ("book_id", Json::Null),
        ("requests", Json::Null),
        ("holder", holder.as_ref().map_or(Json::Null, s)),
    ];
    fields.extend(fad::timed::status_fields(None));
    let data = obj(fields);
    let text = match &holder {
        None => format!("no fad serves {}", dir.display()),
        Some(h) => format!(
            "no fad answers for {}; its writer lease is held by: {h}",
            dir.display()
        ),
    };
    print!("{}", line(json, "fad_status", data, None, &text));
    0
}

fn status(argv: &[String], parsed: &Args, d: &Daemon, dir: &Path) -> u8 {
    let json = parsed.switch("--json");
    let socket = dir.join(&d.socket);
    let Some(holder) = Lease::holder(dir, &d.lease) else {
        return not_serving(dir, &socket, None, json);
    };
    match client::call(&socket, &request(Op::Status, json), d) {
        Ok(response) => {
            print!("{}", response.stdout);
            eprint!("{}", response.stderr);
            response.exit
        }
        Err(ClientError::Connect(_)) => not_serving(dir, &socket, Some(holder), json),
        Err(e) => cli::foundation_error(argv, format!("fad transport: {e}"), false).0,
    }
}

fn stop(argv: &[String], parsed: &Args, d: &Daemon, dir: &Path) -> u8 {
    let json = parsed.switch("--json");
    let socket = dir.join(&d.socket);
    match client::call(&socket, &request(Op::Stop, json), d) {
        Ok(response) => {
            print!("{}", response.stdout);
            eprint!("{}", response.stderr);
            // Return only once the daemon has let go of the book, so the
            // next `fa` command finds the lease free.
            for _ in 0..400 {
                if Lease::holder(dir, &d.lease).is_none() {
                    return response.exit;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            cli::environment_error(
                argv,
                format!(
                    "fad answered stop but still holds {}'s writer lease after 10 s",
                    dir.display()
                ),
                false,
            )
            .0
        }
        Err(ClientError::Connect(e)) => {
            cli::environment_error(
                argv,
                format!(
                    "no fad serves {} ({}: {e})",
                    dir.display(),
                    socket.display()
                ),
                false,
            )
            .0
        }
        Err(e) => cli::foundation_error(argv, format!("fad transport: {e}"), false).0,
    }
}
