//! Preserve parsed command semantics across the embedded-owner daemon route.
//! The transport changes only routing flags, never an intent or a PostPlan.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use crate::args::Args;
use crate::cli::{Files, Stdin};
use crate::verbs::Daemon;
use crate::wire::{Op, Request};

#[derive(Debug)]
pub(super) enum Error {
    Usage(String),
    Environment(String),
}

/// Encode values inline and positionals after a terminator. This preserves
/// values such as `--book`, repeated flags, and literal flags after `--`.
/// Only actual parsed routing flags are removed; the bound book is a flag,
/// never a positional suffix hidden behind the user's terminator.
fn forward_args(parsed: &Args, book: &str) -> Vec<String> {
    let mut argv = Vec::new();
    for (flag, values) in &parsed.flags {
        if flag == "--via" || flag == "--book" {
            continue;
        }
        argv.extend(values.iter().map(|value| format!("{flag}={value}")));
    }
    argv.extend(parsed.switches.iter().cloned());
    argv.push(format!("--book={book}"));
    argv.push("--".into());
    argv.extend(parsed.positional.iter().cloned());
    argv
}

fn wants_stdin(parsed: &Args) -> bool {
    parsed.positional.iter().any(|word| word == "-")
        || parsed.flags.iter().any(|(flag, values)| {
            flag != "--book"
                && flag != "--via"
                && flag != "--format"
                && values.iter().any(|value| value == "-")
        })
}

fn wire_path(path: &Path, what: &str) -> Result<String, Error> {
    path.to_str().map(str::to_string).ok_or_else(|| {
        Error::Environment(format!(
            "{what} is not UTF-8 and cannot be represented by the fad protocol; use a UTF-8 path or --via direct"
        ))
    })
}

/// `dir` has already been resolved against Files.cwd by cli::named_book.
/// Resolve remaining relative paths against ONE process-directory snapshot,
/// not against the daemon or against Files.cwd a second time. A missing cwd
/// is an environment failure, never permission to resolve on the server.
fn paths(dir: &Path, files: &Files) -> Result<(String, String), Error> {
    let needs_process =
        !dir.is_absolute() || files.cwd.as_ref().is_none_or(|path| !path.is_absolute());
    let process = if needs_process {
        std::env::current_dir().map_err(|error| {
            Error::Environment(format!(
                "cannot resolve the client's working directory: {error}"
            ))
        })?
    } else {
        PathBuf::new() // Both paths are already absolute; never used as a base.
    };
    let absolute = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            process.join(path)
        }
    };
    let cwd = files
        .cwd
        .as_deref()
        .map_or_else(|| process.clone(), &absolute);
    Ok((
        wire_path(&absolute(dir), "book path")?,
        wire_path(&cwd, "client working directory")?,
    ))
}

fn input_limit(request: &Request, daemon: &Daemon) -> Result<usize, Error> {
    // With stdin=Some(empty), each additional input byte adds exactly two
    // lowercase hexadecimal characters, with no JSON escaping. Count argv,
    // cwd and the full envelope BEFORE cloning or reading input.
    let overhead = request.to_json(daemon.protocol).render().len();
    let maximum = daemon.max_frame_bytes.min(u32::MAX as usize);
    maximum
        .checked_sub(overhead)
        .map(|remaining| remaining / 2)
        .ok_or_else(|| {
            Error::Usage("command and working directory exceed the daemon frame limit".into())
        })
}

fn oversized() -> Error {
    Error::Usage("stdin exceeds the complete daemon request frame limit; use a readable input file instead of forwarding oversized bytes".into())
}

fn read_input(reader: &mut dyn Read, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    // The limit is at most half u32::MAX, so the sentinel cannot overflow.
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Usage(format!("stdin: {error}")))?;
    if bytes.len() > limit {
        return Err(oversized());
    }
    Ok(bytes)
}

pub(super) fn request(
    parsed: &Args,
    dir: &Path,
    files: &Files,
    daemon: &Daemon,
) -> Result<Request, Error> {
    let (book, cwd) = paths(dir, files)?;
    let mut request = Request {
        op: Op::Run,
        argv: forward_args(parsed, &book),
        cwd: Some(cwd),
        stdin: None,
    };
    let forward = wants_stdin(parsed)
        && match &files.stdin {
            Stdin::Forwarded(_) => true,
            Stdin::Process => !std::io::stdin().is_terminal(),
            Stdin::Missing => false,
        };
    if !forward {
        input_limit(&request, daemon)?; // Also bound requests without stdin.
        return Ok(request);
    }
    request.stdin = Some(Vec::new());
    let limit = input_limit(&request, daemon)?;
    request.stdin = match &files.stdin {
        Stdin::Forwarded(bytes) => {
            if bytes.len() > limit {
                return Err(oversized());
            }
            Some(bytes.clone())
        }
        Stdin::Process => Some(read_input(&mut std::io::stdin().lock(), limit)?),
        Stdin::Missing => None,
    };
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args;
    use crate::verbs;
    use crate::wire;

    fn parse(words: &[&str]) -> Args {
        let reg = verbs::registry().unwrap();
        args::parse(
            &words.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
            &reg.value_flags(),
            &reg.switches(),
        )
        .unwrap()
    }

    fn forwarded(parsed: &Args) -> Args {
        let reg = verbs::registry().unwrap();
        args::parse(
            &forward_args(parsed, "/abs/book"),
            &reg.value_flags(),
            &reg.switches(),
        )
        .unwrap()
    }

    fn files(bytes: Option<Vec<u8>>) -> Files {
        Files {
            cwd: Some(PathBuf::from("/client")),
            stdin: bytes.map_or(Stdin::Missing, Stdin::Forwarded),
        }
    }

    #[test]
    fn transport_rebinds_only_routing_and_preserves_all_other_parsed_fields() {
        for words in [
            vec![
                "tb",
                "--via",
                "fad",
                "--book",
                "rel",
                "--period",
                "P",
                "--via=fad",
                "--json",
            ],
            vec![
                "book", "create", "--name", "--book", "--via", "fad", "--book", "rel",
            ],
            vec![
                "reverse",
                "id",
                "--description",
                "--via=fad",
                "--reason",
                "WrongAccount",
            ],
            vec![
                "post",
                "--intent=-",
                "--grant",
                "read",
                "--grant=post_closed",
                "--json",
                "--json",
            ],
            vec!["help", "--", "--book", "literal", "--via=fad", "--"],
            vec![
                "post",
                "--intent=",
                "--book=-",
                "--via=fad",
                "--",
                "--plan=-",
            ],
        ] {
            let input = parse(&words);
            let output = forwarded(&input);
            let mut expected_flags = input.flags.clone();
            expected_flags.remove("--via");
            expected_flags.insert("--book".into(), vec!["/abs/book".into()]);
            assert_eq!(output.flags, expected_flags, "{words:?}");
            assert_eq!(output.positional, input.positional, "{words:?}");
            assert_eq!(output.switches, input.switches, "{words:?}");
        }
    }

    #[test]
    fn flag_looking_values_survive_a_cross_product_of_supported_value_flags() {
        for flag in [
            "--name",
            "--intent",
            "--description",
            "--key",
            "--plan",
            "--keys",
        ] {
            for value in [
                "--book",
                "--book=other",
                "--via",
                "--via=fad",
                "--",
                "-",
                "",
                "a=b",
                "a b",
            ] {
                for inline in [false, true] {
                    let mut words = vec!["post".to_string()];
                    if inline {
                        words.push(format!("{flag}={value}"));
                    } else {
                        words.extend([flag.into(), value.into()]);
                    }
                    let parsed = parse(&words.iter().map(String::as_str).collect::<Vec<_>>());
                    let output = forwarded(&parsed);
                    assert_eq!(output.flag_all(flag), vec![value], "{words:?}");
                    assert_eq!(output.positional, vec!["post"]);
                    assert_eq!(output.flag("--book"), Some("/abs/book"));
                }
            }
        }
    }

    #[test]
    fn inline_and_separate_stdin_selectors_deliver_identical_binary_bytes() {
        let bytes = vec![0, 255, 13, 10, b'F', b'A'];
        let daemon = &verbs::registry().unwrap().daemon;
        for (inline, separate) in [
            (vec!["commit", "--plan=-"], vec!["commit", "--plan", "-"]),
            (vec!["post", "--intent=-"], vec!["post", "--intent", "-"]),
        ] {
            let a = request(
                &parse(&inline),
                Path::new("/book"),
                &files(Some(bytes.clone())),
                daemon,
            )
            .unwrap();
            let b = request(
                &parse(&separate),
                Path::new("/book"),
                &files(Some(bytes.clone())),
                daemon,
            )
            .unwrap();
            assert_eq!(a, b);
            assert_eq!(a.stdin, Some(bytes.clone()));
            let json = wire::canonical(a.to_json(daemon.protocol).render().as_bytes()).unwrap();
            assert_eq!(Request::from_json(&json, daemon.protocol).unwrap(), a);
        }
    }

    #[test]
    fn absent_and_empty_stdin_remain_distinct_and_unused_bytes_are_not_sent() {
        let parsed = parse(&["commit", "--plan=-"]);
        let daemon = &verbs::registry().unwrap().daemon;
        assert_eq!(
            request(&parsed, Path::new("/book"), &files(None), daemon)
                .unwrap()
                .stdin,
            None
        );
        assert_eq!(
            request(
                &parsed,
                Path::new("/book"),
                &files(Some(Vec::new())),
                daemon
            )
            .unwrap()
            .stdin,
            Some(Vec::new())
        );
        for words in [
            vec!["book", "info"],
            vec!["tb", "--book=-"],
            vec!["help", "--", "--plan=-"],
        ] {
            assert_eq!(
                request(
                    &parse(&words),
                    Path::new("/book"),
                    &files(Some(vec![7])),
                    daemon
                )
                .unwrap()
                .stdin,
                None
            );
        }
    }

    #[test]
    fn frame_budget_includes_json_envelope_escaping_and_hex_expansion() {
        let parsed = parse(&["commit", "--plan=-", "--description=\"quoted\\path\""]);
        let mut daemon = verbs::registry().unwrap().daemon.clone();
        let base = request(
            &parsed,
            Path::new("/book"),
            &files(Some(Vec::new())),
            &daemon,
        )
        .unwrap();
        let overhead = base.to_json(daemon.protocol).render().len();
        for size in [0, 1, 7, 257] {
            daemon.max_frame_bytes = overhead + size * 2;
            let exact = request(
                &parsed,
                Path::new("/book"),
                &files(Some(vec![255; size])),
                &daemon,
            )
            .unwrap();
            assert_eq!(
                exact.to_json(daemon.protocol).render().len(),
                daemon.max_frame_bytes
            );
            assert!(matches!(
                request(
                    &parsed,
                    Path::new("/book"),
                    &files(Some(vec![255; size + 1])),
                    &daemon
                ),
                Err(Error::Usage(_))
            ));
            daemon.max_frame_bytes += 1;
            assert!(matches!(
                request(
                    &parsed,
                    Path::new("/book"),
                    &files(Some(vec![255; size + 1])),
                    &daemon
                ),
                Err(Error::Usage(_))
            ));
        }
        daemon.max_frame_bytes = overhead - 1;
        assert!(matches!(
            request(
                &parsed,
                Path::new("/book"),
                &files(Some(Vec::new())),
                &daemon
            ),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            request(&parsed, Path::new("/book"), &files(None), &daemon),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn stream_reader_stops_at_one_sentinel_byte_over_the_limit() {
        let mut input = std::io::Cursor::new(vec![42; 1000]);
        assert!(matches!(read_input(&mut input, 7), Err(Error::Usage(_))));
        assert_eq!(input.position(), 8, "never drain an oversized pipe");
        assert_eq!(
            read_input(&mut std::io::Cursor::new(vec![42; 7]), 7).unwrap(),
            vec![42; 7]
        );
        assert_eq!(
            read_input(&mut std::io::Cursor::new(Vec::new()), 0).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stream_errors_do_not_turn_partial_input_into_a_request() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected stdin failure"))
            }
        }
        assert!(
            matches!(read_input(&mut Broken, 100), Err(Error::Usage(message)) if message.contains("injected stdin failure"))
        );
    }

    #[test]
    fn relative_file_context_is_made_absolute_once_without_daemon_fallback() {
        let mut context = files(None);
        context.cwd = Some(PathBuf::from("relative-client"));
        let (book, cwd) = paths(Path::new("relative-client/book"), &context).unwrap();
        let process = std::env::current_dir().unwrap();
        assert_eq!(PathBuf::from(book), process.join("relative-client/book"));
        assert_eq!(PathBuf::from(cwd), process.join("relative-client"));
        let (book, cwd) = paths(
            Path::new("/book"),
            &Files {
                cwd: None,
                stdin: Stdin::Missing,
            },
        )
        .unwrap();
        assert_eq!(book, "/book");
        assert_eq!(PathBuf::from(cwd), process);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_refuse_instead_of_selecting_a_lossy_different_path() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let bad = PathBuf::from(OsString::from_vec(b"/client-\xff".to_vec()));
        assert!(matches!(
            paths(&bad, &files(None)),
            Err(Error::Environment(_))
        ));
        let mut context = files(None);
        context.cwd = Some(bad);
        assert!(matches!(
            paths(Path::new("/book"), &context),
            Err(Error::Environment(_))
        ));
    }
}
