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
    // Never silent on a panic (fa-y9z): one FA-REF-153 error event, exit 5.
    fa_cli::panic::install("fad");
    ExitCode::from(fa_cli::panic::run_reporting(&argv, || {
        // Debug builds only: the never-silent-fail test's deliberate panic.
        #[cfg(debug_assertions)]
        if std::env::var_os("FA_TEST_PANIC").is_some() {
            std::panic::panic_any(
                "FA_TEST_PANIC: a deliberate panic for the never-silent-fail test",
            );
        }
        run(&argv)
    }))
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
    let mut flags: Vec<&str> = d.flags.iter().map(String::as_str).collect();
    for flag in ["--mcp", "--token", "--cluster"] {
        if !flags.contains(&flag) {
            flags.push(flag);
        }
    }
    let mut switches: Vec<&str> = d.switches.iter().map(String::as_str).collect();
    if !switches.contains(&"--version") {
        switches.push("--version");
    }
    let parsed = match args::parse(argv, &flags, &switches) {
        Ok(a) => a,
        Err(e) => return cli::usage_error(argv, e.message, e.fix, false).0,
    };
    if parsed.switch("--version") {
        if parsed.switch("--json") {
            println!("{}", cli::version_metadata_json(&d.binary).render());
        } else {
            println!("{}", cli::version_text(&d.binary));
        }
        return 0;
    }
    let verb = parsed.positional.first().map(String::as_str);
    if verb.is_none() || parsed.switch("--help") {
        let mut text = format!("{} — the FrankenAccounting daemon\n\nusage\n", d.binary);
        for u in &d.usage {
            text.push_str(&format!("  {u}\n"));
        }
        text.push_str("  fad serve --book <dir> --mcp stdio|socket [--token <file>] [--cluster <name|all> ...] [--files-root <dir>]\n");
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
    if parsed.flag("--files-root").is_some() && verb != Some("serve") {
        return cli::usage_error(
            argv,
            "--files-root is a local daemon launch containment choice for serve",
            "fad serve --book <dir> --files-root <dir>",
            false,
        )
        .0;
    }
    if parsed.flag_all("--files-root").len() > 1 {
        return cli::usage_error(
            argv,
            "--files-root may be supplied at most once",
            "fad serve --book <dir> --files-root <dir>",
            false,
        )
        .0;
    }
    let register_periods: Vec<String> = parsed
        .flag_all("--register-period")
        .into_iter()
        .map(str::to_owned)
        .collect();
    let fiscal_years = parsed.flag_all("--register-fiscal-year");
    let register_fiscal_year = if fiscal_years.is_empty() {
        None
    } else {
        if verb != Some("serve") || fiscal_years.len() != 1 || !register_periods.is_empty() {
            return cli::usage_error(
                argv,
                "--register-fiscal-year selects one year for serve and cannot be combined with --register-period",
                "fad serve --book <dir> --register-fiscal-year <year>",
                false,
            ).0;
        }
        match fiscal_years[0].parse::<i32>() {
            Ok(year) => Some(year),
            Err(_) => {
                return cli::usage_error(
                    argv,
                    "--register-fiscal-year needs an integer fiscal year",
                    "fad serve --book <dir> --register-fiscal-year 2026",
                    false,
                )
                .0;
            }
        }
    };
    if !register_periods.is_empty() {
        if verb != Some("serve") {
            return cli::usage_error(
                argv,
                "--register-period is a local daemon launch choice for serve",
                "fad serve --book <dir> --register-period <code>",
                false,
            )
            .0;
        }
        if let Err(error) = fad::timed::registers::validate_periods(&register_periods) {
            return cli::usage_error(
                argv,
                error.to_string(),
                "supply 1..=64 distinct --register-period <exact-code> options",
                false,
            )
            .0;
        }
    }
    if (parsed.flag("--mcp").is_some()
        || parsed.flag("--token").is_some()
        || !parsed.flag_all("--cluster").is_empty())
        && verb != Some("serve")
    {
        return cli::usage_error(
            argv,
            "--mcp, --token and --cluster are local daemon launch options for `fad serve`",
            "fad serve --book <dir> --mcp stdio --token <file>",
            false,
        )
        .0;
    }
    if parsed.flag_all("--mcp").len() > 1 {
        return cli::usage_error(
            argv,
            "--mcp may be supplied at most once",
            "fad serve --book <dir> --mcp stdio|socket",
            false,
        )
        .0;
    }
    if parsed.flag_all("--token").len() > 1 {
        return cli::usage_error(
            argv,
            "--token may be supplied at most once",
            "fad serve --book <dir> --mcp stdio --token <file>",
            false,
        )
        .0;
    }
    match verb {
        Some("serve") => serve(argv, &parsed, d, &dir, register_fiscal_year),
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

fn fa_mcp_binary() -> PathBuf {
    if let Ok(bin) = std::env::var("FA_MCP_BIN")
        && !bin.is_empty()
    {
        return PathBuf::from(bin);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let sibling = parent.join("fa-mcp");
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("fa-mcp")
}

fn serve(
    argv: &[String],
    parsed: &Args,
    d: &Daemon,
    dir: &Path,
    register_fiscal_year: Option<i32>,
) -> u8 {
    let json = parsed.switch("--json");
    let mcp_mode = match parsed.flag("--mcp") {
        None => None,
        Some(mode @ ("stdio" | "socket")) => Some(mode),
        Some(other) => {
            return cli::usage_error(
                argv,
                format!("invalid --mcp mode `{other}`; expected `stdio` or `socket`"),
                "fad serve --book <dir> --mcp stdio --token <file>",
                false,
            )
            .0;
        }
    };
    let mcp_stdio = mcp_mode == Some("stdio");
    let token_path = parsed.flag("--token").map(PathBuf::from).or_else(|| {
        std::env::var("FA_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .map(PathBuf::from)
    });
    if (token_path.is_some() || !parsed.flag_all("--cluster").is_empty()) && mcp_mode.is_none() {
        return cli::usage_error(
            argv,
            "--token and --cluster on `fad serve` require `--mcp stdio|socket`",
            "fad serve --book <dir> --mcp stdio --token <file>",
            false,
        )
        .0;
    }
    let hosted_token = if mcp_stdio {
        let Some(path) = &token_path else {
            return cli::usage_error(
                argv,
                "`fad serve --mcp stdio` requires `--token <file>` (or FA_TOKEN) to bind the hosted MCP session's capability",
                "fad serve --book <dir> --mcp stdio --token <file>",
                false,
            )
            .0;
        };
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return cli::usage_error(
                    argv,
                    format!(
                        "--token {}: cannot read the token file: {e}",
                        path.display()
                    ),
                    "supply a readable token file produced by `fa capability issue`",
                    false,
                )
                .0;
            }
        };
        let token = match fa_cli::authority::CapabilityToken::decode(&bytes) {
            Ok(t) => t,
            Err(e) => {
                return cli::usage_error(
                    argv,
                    format!("--token {}: {e}", path.display()),
                    "supply a valid token file produced by `fa capability issue`",
                    false,
                )
                .0;
            }
        };
        let authority =
            match fa_cli::authority::LaunchAuthority::from_token(dir.to_path_buf(), None, &token) {
                Ok(a) => a,
                Err(e) => {
                    return cli::usage_error(
                        argv,
                        format!("--token {}: {e}", path.display()),
                        "supply a token whose profile is admissible for MCP (agent or preparer)",
                        false,
                    )
                    .0;
                }
            };
        Some((path.clone(), authority))
    } else {
        None
    };
    let files_root = match parsed.flag("--files-root") {
        Some(raw) => match fa_cli::authority::validate_files_root(PathBuf::from(raw)) {
            Ok(root) => {
                let canon_book = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
                if root.starts_with(&canon_book) {
                    return cli::usage_error(
                        argv,
                        format!(
                            "invalid --files-root: --files-root `{}` may not be the book directory or inside it",
                            root.display()
                        ),
                        "supply an existing non-symlink directory distinct from --book",
                        false,
                    )
                    .0;
                }
                Some(root)
            }
            Err(reason) => {
                return cli::usage_error(
                    argv,
                    format!("invalid --files-root: {reason}"),
                    "supply an existing non-symlink directory distinct from --book",
                    false,
                )
                .0;
            }
        },
        None => None,
    };
    let socket = dir.join(&d.socket);
    let keys_file = parsed
        .flag("--keys")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("book.keys"));
    let keys = match BookKeys::load(&keys_file) {
        Ok(k) => k,
        Err(e) => return cli::book_error(argv, e, false).0,
    };
    if !Lease::is_book_dir(dir) {
        return cli::book_error(argv, fa::book::BookError::NoBook, false).0;
    }
    let note = format!("fad pid={} socket={}", std::process::id(), socket.display());
    let lease = match Lease::acquire(dir, &d.lease, &note) {
        Ok(l) => l,
        Err(e @ LeaseError::Held { .. }) => return cli::refuse(argv, e.refusal(dir), false).0,
        Err(e) => return cli::environment_error(argv, e.to_string(), false).0,
    };
    let mut book = match Book::open_dir(dir, keys, Entropy::production()) {
        Ok(b) => b,
        Err(e) => return cli::book_error(argv, e, false).0,
    };
    // Resolve before socket cleanup/bind or timed work. This is the book's
    // calendar, including custom and special periods, not a guessed code list.
    let periods = match register_fiscal_year {
        Some(year) => match fad::timed::registers::fiscal_year_periods(&book.context().calendar, year) {
            Ok(periods) => periods,
            Err(error) => return cli::usage_error(
                argv,
                format!("--register-fiscal-year {year}: {error}"),
                "choose a fiscal year the book calendar defines, or select exact --register-period codes",
                false,
            ).0,
        },
        None => parsed.flag_all("--register-period").into_iter().map(str::to_owned).collect(),
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
    let timed = if parsed.switch("--bootstrap-system") || !periods.is_empty() {
        let policy = match fad::timed::Policy::from_registry(d) {
            Ok(policy) => policy,
            Err(error) => return cli::foundation_error(argv, error.to_string(), false).0,
        };
        if parsed.switch("--bootstrap-system") {
            match fad::timed::TimedWork::bootstrap(&cx, &book, policy) {
                Ok(work) if periods.is_empty() => Some(work),
                Ok(work) => match work.with_register_maintenance(periods) {
                    Ok(work) => Some(work),
                    Err(error) => return cli::foundation_error(argv, error.to_string(), false).0,
                },
                // Explicit timed accounting effects never silently fall back.
                Err(error) => return cli::foundation_error(argv, error.to_string(), false).0,
            }
        } else {
            match fad::timed::TimedWork::maintenance_only(&cx, policy, periods) {
                Ok(work) => Some(work),
                Err(error) => return cli::foundation_error(argv, error.to_string(), false).0,
            }
        }
    } else {
        None
    };
    let limits = Limits::from_registry(d);
    let book_id = book.context().book_id.to_hex();
    let at = match book.head() {
        Ok(known_at) => cli::At {
            book: book_id.clone(),
            branch: "trunk".into(),
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
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod 0700 {}: {e}", dir.display()))?;
        }
        let listener = UnixListener::bind(&socket)
            .await
            .map_err(|e| format!("bind {}: {e}", socket.display()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod 0600 {}: {e}", socket.display()))?;
        }
        let daemon_uid =
            fad::current_uid().map_err(|e| format!("daemon peer credential uid: {e}"))?;
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
        let serving_line = line(
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
        );
        if mcp_stdio {
            eprint!("{serving_line}");
        } else {
            print!("{serving_line}");
        }
        let mut server = Server {
            book: &mut book,
            dir: dir.to_path_buf(),
            socket: socket.clone(),
            files_root: files_root.clone(),
            requests: 0,
            timed,
            daemon_uid: Some(daemon_uid),
            timings: Vec::new(),
        };
        let served = if let Some((token_file, authority)) = &hosted_token {
            if let Ok(Err(refusal)) = server.book.admit_current(authority.capability()) {
                drop(listener);
                let _ = region.close().await;
                return Err(format!("token refused by book: {}", refusal.message));
            }
            let mut cmd = std::process::Command::new(fa_mcp_binary());
            cmd.arg("--book")
                .arg(dir)
                .arg("--token")
                .arg(token_file)
                .env_remove("FA_BOOK")
                .env_remove("FA_TOKEN");
            if let Some(root) = &files_root {
                cmd.arg("--files").arg(root);
            }
            for cluster in parsed.flag_all("--cluster") {
                cmd.arg("--cluster").arg(cluster);
            }
            let mut child = cmd
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .map_err(|e| format!("spawn fa-mcp: {e}"))?;
            let res = fad::serve_book_until(region.cx(), &listener, limits, &mut server, || {
                child.try_wait().ok().flatten().is_some()
            })
            .await;
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let status = child.wait().map_err(|e| format!("wait fa-mcp: {e}"))?;
            if !status.success() {
                drop(listener);
                let _ = region.close().await;
                return Err(format!(
                    "hosted fa-mcp exited with status {:?}",
                    status.code()
                ));
            }
            res
        } else {
            fad::serve_book(region.cx(), &listener, limits, &mut server).await
        };
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
            let stopped_line = line(
                json,
                "fad_stopped",
                stopped,
                None,
                &format!(
                    "fad for {} stopped after {requests} requests; the writer lease is released",
                    dir.display()
                ),
            );
            if mcp_stdio {
                eprint!("{stopped_line}");
            } else {
                print!("{stopped_line}");
            }
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
        token: None,
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
    let keys_file = parsed
        .flag("--keys")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("book.keys"));
    let mut req = request(Op::Stop, json);
    req.stdin = BookKeys::load(&keys_file)
        .ok()
        .map(|keys| keys.owner_token().to_vec());
    match client::call(&socket, &req, d) {
        Ok(response) => {
            print!("{}", response.stdout);
            eprint!("{}", response.stderr);
            if response.exit != 0 {
                return response.exit;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_reports_foundation_revisions_and_registry_epochs() {
        let code = run(&["--version".to_string()]);
        assert_eq!(code, 0);
        let code_json = run(&["--version".to_string(), "--json".to_string()]);
        assert_eq!(code_json, 0);

        let text = cli::version_text("fa");
        assert!(text.starts_with("fa "), "{text}");
        assert!(text.contains("asupersync@78b64636"), "{text}");
        assert!(text.contains("frankengraphdb@b323bd17"), "{text}");
        assert!(text.contains("franken_networkx@9d710b1c"), "{text}");
        assert!(text.contains("fastmcp-rust@=0.12.0"), "{text}");
        assert!(text.contains("frankensympy@bd1ad68a"), "{text}");
        assert!(text.contains("registries: schema_v=1, epochs=15"), "{text}");

        let meta = cli::version_metadata_json("fad");
        assert_eq!(meta.get("binary").and_then(Json::as_str), Some("fad"));
        let foundations = meta
            .get("foundations")
            .and_then(Json::as_arr)
            .expect("foundations array");
        assert_eq!(foundations.len(), 5);
        let epochs = meta
            .get("registry_epochs")
            .and_then(Json::as_arr)
            .expect("registry_epochs array");
        // The stack lock is itself a registry epoch; the older count of
        // fourteen omitted its registered `foundations` fingerprint.
        let names: Vec<&str> = epochs
            .iter()
            .map(|epoch| {
                epoch
                    .get("name")
                    .and_then(Json::as_str)
                    .expect("epoch name")
            })
            .collect();
        assert_eq!(
            names,
            [
                "account_types",
                "admissibility",
                "entry_classes",
                "exit_codes",
                "foundation_dependencies",
                "invariants",
                "intents",
                "limits",
                "procedures",
                "reason_codes",
                "rounding_laws",
                "symbols",
                "units",
                "verbs",
                "foundations",
            ]
        );
        for epoch in epochs {
            let digest = epoch
                .get("canonical_digest")
                .and_then(Json::as_str)
                .expect("canonical_digest");
            assert_eq!(digest.len(), 64);
            assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }
}
