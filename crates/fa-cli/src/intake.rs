//! Bounded document input for both direct commands and forwarded daemon input.
//!
//! The byte limit applies while reading, not after an unbounded allocation or
//! a metadata-size check. Each read observes at most its remaining budget plus
//! one sentinel byte. No truncated prefix is ever returned as a document.

use std::io::{self, Read};

use fa_journal::refusal::{Refusal, code, exit};
use fa_registry::document_stores::DocumentStores;

use crate::cli::{Fail, Files, Stdin, usage};

/// Host transport bound, not a limit on the amount of evidence a book retains.
/// An import exceeding this total must be split into explicitly separate runs.
/// Bound the complete batch before constructing or hashing any `Document`
/// objects; buffer capacities and kernel encodings have additional overhead.
pub(crate) const MAX_INTAKE_BATCH_BYTES: u64 = 64 * 1024 * 1024;
const BUFFER_BYTES: usize = 8192;

fn oversized(what: &str, limit: u64) -> Fail {
    Fail::Refusal(Refusal::new(
        code::DOCUMENT_INTAKE,
        exit::USAGE,
        format!("{what} exceeds the remaining document input budget of {limit} bytes"),
        "plan §9.1–§9.3; bounded Docket input; registries/document_stores.toml",
        "split the input into smaller documents or separate explicit import runs; no document or import receipt was recorded",
    ))
}

fn io_failed(what: &str, error: io::Error) -> Fail {
    usage(
        format!("{what}: {error}"),
        "pass a readable file, or forward its complete bytes on stdin with -",
    )
}

/// Never reserve from a file's claimed metadata size, nor from the whole
/// allowed budget. Grow only for observed bytes, geometrically, capped at the
/// admitted limit. Allocation failures are ordinary I/O failures, not panics.
fn append(out: &mut Vec<u8>, bytes: &[u8], limit: usize) -> io::Result<()> {
    let needed = out
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "document length overflow"))?;
    if needed > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "document exceeds budget",
        ));
    }
    if needed > out.capacity() {
        let capacity = out.capacity().saturating_mul(2).max(needed).min(limit);
        out.try_reserve_exact(capacity - out.len())
            .map_err(io::Error::other)?;
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_retry(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn read_bounded(reader: &mut impl Read, limit: u64, what: &str) -> Result<Vec<u8>, Fail> {
    let limit_bytes = limit;
    let limit = usize::try_from(limit).map_err(|_| {
        Fail::Internal("document input limit is not addressable on this host".into())
    })?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; BUFFER_BYTES];
    while bytes.len() < limit {
        let available = (limit - bytes.len()).min(buffer.len());
        let count =
            read_retry(reader, &mut buffer[..available]).map_err(|error| io_failed(what, error))?;
        if count > available {
            return Err(io_failed(
                what,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input reader reported more bytes than its buffer holds",
                ),
            ));
        }
        if count == 0 {
            return Ok(bytes);
        }
        append(&mut bytes, &buffer[..count], limit).map_err(|error| io_failed(what, error))?;
    }
    // At the exact limit, distinguish EOF from truncation without appending
    // or allocating a sentinel. This also handles a zero remaining budget.
    let count = read_retry(reader, &mut buffer[..1]).map_err(|error| io_failed(what, error))?;
    if count == 0 {
        Ok(bytes)
    } else {
        Err(oversized(what, limit_bytes))
    }
}

fn read_one(files: &Files, path: &str, limit: u64) -> Result<Vec<u8>, Fail> {
    if path == "-" {
        return match &files.stdin {
            Stdin::Forwarded(bytes) => {
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
                    return Err(oversized("forwarded document", limit));
                }
                // Reject before cloning. Forwarded input may already exist in
                // the outer transport, but intake must not allocate it again
                // before checking this smaller operation-specific budget.
                let mut out = Vec::new();
                out.try_reserve_exact(bytes.len())
                    .map_err(|error| io_failed("forwarded document", io::Error::other(error)))?;
                out.extend_from_slice(bytes);
                Ok(out)
            }
            Stdin::Missing => Err(usage(
                "`-` names stdin, but no input reached the daemon",
                "forward the document bytes on stdin, or pass an admitted file path",
            )),
            Stdin::Process => read_bounded(&mut io::stdin().lock(), limit, "stdin document"),
        };
    }
    let mut file =
        std::fs::File::open(files.resolve(path)).map_err(|error| io_failed(path, error))?;
    read_bounded(&mut file, limit, path)
}

fn document_limit() -> Result<u64, Fail> {
    let stores = DocumentStores::embedded()
        .map_err(|error| Fail::Internal(format!("the embedded document stores: {error}")))?;
    let store = stores
        .get(1)
        .ok_or_else(|| Fail::Internal("the book's document store (1) is not registered".into()))?;
    Ok(store.max_document_bytes.min(MAX_INTAKE_BATCH_BYTES))
}

fn check_paths(paths: &[&str], max_documents: usize) -> Result<(), Fail> {
    if paths.is_empty() || paths.len() > max_documents {
        return Err(Fail::Refusal(Refusal::new(
            code::DOCUMENT_INTAKE,
            exit::USAGE,
            format!(
                "document input needs 1..={max_documents} files; received {}",
                paths.len()
            ),
            "plan §9.3; max_import_documents",
            "split the input into explicit bounded import runs",
        )));
    }
    if paths.iter().filter(|path| **path == "-").count() > 1 {
        return Err(usage(
            "an import can consume stdin only once",
            "use - for exactly one document and file paths for the others",
        ));
    }
    Ok(())
}

fn read_documents_with(
    files: &Files,
    paths: &[&str],
    per_document: u64,
    total: u64,
    max_documents: usize,
) -> Result<Vec<Vec<u8>>, Fail> {
    // Check the entire selection before opening the first file. In particular,
    // repeated stdin cannot mean the same forwarded bytes twice in a daemon
    // but a consumed/empty stream in a direct command.
    check_paths(paths, max_documents)?;
    let mut remaining = total;
    let mut documents = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = read_one(files, path, per_document.min(remaining))?;
        let consumed = u64::try_from(bytes.len())
            .map_err(|_| Fail::Internal("document size exceeds u64".into()))?;
        remaining = remaining
            .checked_sub(consumed)
            .ok_or_else(|| Fail::Internal("document input budget underflow".into()))?;
        documents.push(bytes);
    }
    Ok(documents)
}

pub(crate) fn read_document(files: &Files, path: &str) -> Result<Vec<u8>, Fail> {
    read_one(files, path, document_limit()?)
}

pub(crate) fn read_documents(files: &Files, paths: &[&str]) -> Result<Vec<Vec<u8>>, Fail> {
    read_documents_with(
        files,
        paths,
        document_limit()?,
        MAX_INTAKE_BATCH_BYTES,
        fa_model::limits::MAX_IMPORT_DOCUMENTS,
    )
}

/// Validate count and stream selection before opening the book as well as
/// before consuming input. Kept separate from the reader so authority may be
/// checked between structural validation and actual input consumption.
pub(crate) fn validate_documents(paths: &[&str]) -> Result<(), Fail> {
    check_paths(paths, fa_model::limits::MAX_IMPORT_DOCUMENTS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ok(result: Result<Vec<u8>, Fail>) -> Vec<u8> {
        match result {
            Ok(bytes) => bytes,
            Err(_) => panic!("expected complete bounded input"),
        }
    }

    fn is_limit(result: Result<Vec<u8>, Fail>) {
        assert!(matches!(
            result,
            Err(Fail::Refusal(Refusal {
                code: code::DOCUMENT_INTAKE,
                exit: exit::USAGE,
                ..
            }))
        ));
    }

    #[test]
    fn exact_limit_is_not_truncated_and_one_more_byte_is_refused() {
        for size in [0_usize, 1, BUFFER_BYTES - 1, BUFFER_BYTES, BUFFER_BYTES + 1] {
            let expected = vec![0x73; size];
            assert_eq!(
                ok(read_bounded(
                    &mut Cursor::new(&expected),
                    size as u64,
                    "test"
                )),
                expected
            );
            let excess = vec![0x73; size + 1];
            let mut reader = Cursor::new(excess);
            is_limit(read_bounded(&mut reader, size as u64, "test"));
            assert_eq!(reader.position(), size as u64 + 1);
        }
    }

    struct Infinite {
        observed: usize,
    }

    impl Read for Infinite {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            out.fill(1);
            self.observed += out.len();
            Ok(out.len())
        }
    }

    #[test]
    fn nonterminating_inputs_stop_after_one_sentinel() {
        let mut source = Infinite { observed: 0 };
        is_limit(read_bounded(&mut source, 17, "infinite"));
        assert_eq!(source.observed, 18);
    }

    struct Interrupted {
        source: Cursor<Vec<u8>>,
        interrupt: bool,
    }

    impl Read for Interrupted {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                let count = out.len().min(2);
                self.source.read(&mut out[..count])
            }
        }
    }

    #[test]
    fn interrupted_and_short_reads_preserve_every_binary_byte() {
        let expected = vec![0, 255, 128, 13, 10, 7, 0];
        let mut source = Interrupted {
            source: Cursor::new(expected.clone()),
            interrupt: false,
        };
        assert_eq!(
            ok(read_bounded(&mut source, expected.len() as u64, "binary")),
            expected
        );
    }

    struct Failing {
        delivered: bool,
    }

    impl Read for Failing {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.delivered {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            } else {
                self.delivered = true;
                out[0] = 9;
                Ok(1)
            }
        }
    }

    #[test]
    fn io_failure_never_becomes_a_successful_prefix() {
        for limit in [1, 100] {
            let result = read_bounded(&mut Failing { delivered: false }, limit, "broken");
            assert!(matches!(result, Err(Fail::Usage(_))));
        }
    }

    #[test]
    fn forwarded_bytes_obey_the_same_limit_without_utf8_conversion() {
        let files = Files {
            cwd: None,
            stdin: Stdin::Forwarded(vec![0, 255, 1]),
        };
        assert_eq!(ok(read_one(&files, "-", 3)), [0, 255, 1]);
        is_limit(read_one(&files, "-", 2));
        assert!(matches!(
            read_one(
                &Files {
                    cwd: None,
                    stdin: Stdin::Missing
                },
                "-",
                3
            ),
            Err(Fail::Usage(_))
        ));
    }

    #[test]
    fn selection_errors_precede_any_attempt_to_open_input() {
        let files = Files::default();
        assert!(matches!(
            read_documents_with(&files, &["must-not-open", "-", "-"], 4, 8, 3),
            Err(Fail::Usage(_))
        ));
        assert!(matches!(
            read_documents_with(&files, &["must-not-open", "also-must-not-open"], 4, 8, 1),
            Err(Fail::Refusal(_))
        ));
        assert!(matches!(
            read_documents_with(&files, &[], 4, 8, 1),
            Err(Fail::Refusal(_))
        ));
    }

    #[test]
    fn reader_can_never_force_allocation_from_its_claimed_read_count() {
        struct Liar;
        impl Read for Liar {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Ok(usize::MAX)
            }
        }
        assert!(matches!(
            read_bounded(&mut Liar, 4, "bad reader"),
            Err(Fail::Usage(_))
        ));
    }

    #[test]
    fn aggregate_budget_counts_every_file_and_exact_total_is_admitted() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "fa-intake-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        // create_dir refuses an existing location; the test never reuses it.
        std::fs::create_dir(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        std::fs::write(directory.join("one"), [0, 255, 1, 2]).unwrap();
        std::fs::write(directory.join("two"), [3, 4, 5, 6]).unwrap();
        let files = Files {
            cwd: Some(directory),
            stdin: Stdin::Missing,
        };
        let paths = ["one", "two"];
        let exact = match read_documents_with(&files, &paths, 4, 8, 2) {
            Ok(documents) => documents,
            Err(_) => panic!("exact aggregate limit must be admitted"),
        };
        assert_eq!(exact, vec![vec![0, 255, 1, 2], vec![3, 4, 5, 6]]);
        assert!(matches!(
            read_documents_with(&files, &paths, 4, 7, 2),
            Err(Fail::Refusal(_))
        ));
        assert!(matches!(
            read_documents_with(&files, &paths, 3, 8, 2),
            Err(Fail::Refusal(_))
        ));
    }

    #[test]
    fn registered_document_limit_never_exceeds_transport_budget() {
        let limit = match document_limit() {
            Ok(n) => n,
            Err(_) => panic!("registered store"),
        };
        assert!(limit > 0 && limit <= MAX_INTAKE_BATCH_BYTES);
    }
}
