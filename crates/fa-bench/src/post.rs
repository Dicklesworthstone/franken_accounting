//! The write path (plan §17, FA-BENCH-01 and FA-BENCH-02, fa-ykbp): single
//! posts and atomic batches of 100 into a directory book, so every commit
//! pays the book's own durable syncs on the target filesystem.
//!
//! Each timed operation is one `Book::post` or one `Book::post_batch` of
//! fresh intents. The work witness is the engine's own count of entries it
//! newly recorded: an identical retry the kernel answers from its recorded
//! outcome writes nothing and counts nothing.

use std::path::Path;
use std::time::Instant;

use fa::book::{Book, BookKeys, Entropy};
use fa_journal::{PostBatch, PostIntent, PostRequest, Posted};
use fa_model::Id128;

use crate::BenchError;
use crate::rebuild::{Ledger, exec, spec};

/// Members of one FA-BENCH-02 batch (its counting unit, `batch_100_entries`).
pub const BATCH_ENTRIES: u64 = 100;

/// A directory book ready for timed posts.
pub struct PostBook {
    ledger: Ledger,
    next: u64,
}

/// One timed write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    pub elapsed_us: u64,
    /// Entries the engine newly recorded in this write.
    pub committed: u64,
}

/// Create a directory book at `dir`, which must not exist yet, and prepare
/// it. Amounts come from `seed`.
pub fn build(dir: &Path, seed: u64) -> Result<PostBook, BenchError> {
    if dir.exists() {
        return Err(BenchError::Execution(format!(
            "{} exists; a write-path bench creates its book in a new directory",
            dir.display()
        )));
    }
    let book_id = Id128(*b"FA-BENCH-POSTING");
    let (spec, usd) = spec(book_id, "Bench Posting Book")?;
    let book = Book::create_dir(
        dir,
        BookKeys::for_development(13),
        spec,
        Entropy::deterministic(13),
    )
    .map_err(exec)?;
    Ok(PostBook {
        ledger: Ledger::prepare(book, book_id, usd, seed)?,
        next: 0,
    })
}

fn micros(start: Instant) -> Result<u64, BenchError> {
    u64::try_from(start.elapsed().as_micros()).map_err(exec)
}

impl PostBook {
    /// Post the next entry of the stream on its own, timed.
    pub fn post_one(&mut self) -> Result<Written, BenchError> {
        let intent = self.ledger.entry("post", self.next)?;
        self.next += 1;
        self.post_intent(&intent)
    }

    /// Post `intent`, timed; `committed` is 1 only when the engine recorded
    /// a new entry.
    fn post_intent(&mut self, intent: &PostIntent) -> Result<Written, BenchError> {
        let request = PostRequest {
            proposal: intent.proposal().clone(),
            approvals: Vec::new(),
            plan_certificate: None,
            capability: self.ledger.post.clone(),
        };
        let start = Instant::now();
        let posted = self
            .ledger
            .book
            .post(request)
            .map_err(exec)?
            .map_err(|r| exec(r.message))?;
        Ok(Written {
            elapsed_us: micros(start)?,
            committed: u64::from(matches!(posted, Posted::Committed { .. })),
        })
    }

    /// Post the next [`BATCH_ENTRIES`] entries of the stream as one atomic
    /// batch, timed.
    pub fn post_batch(&mut self) -> Result<Written, BenchError> {
        let first = self.next;
        let members = (first..first + BATCH_ENTRIES)
            .map(|i| self.ledger.entry("batch", i))
            .collect::<Result<Vec<_>, _>>()?;
        self.next += BATCH_ENTRIES;
        // Batches and posts share one outcome-key namespace, so the batch's
        // own key must differ from every member's (`bench:batch:<i>`).
        let batch = PostBatch::new(format!("bench:batch-of:{first}").into_bytes(), members)
            .map_err(exec)?;
        let start = Instant::now();
        let posted = self
            .ledger
            .book
            .post_batch(batch, &self.ledger.post)
            .map_err(exec)?
            .map_err(|r| exec(r.message))?;
        let elapsed_us = micros(start)?;
        Ok(Written {
            elapsed_us,
            committed: if posted.already_recorded {
                0
            } else {
                posted.entries.len() as u64
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "fa-bench-post-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn every_timed_write_commits_what_it_claims() {
        let dir = fresh("count");
        let mut book = build(&dir, 42).expect("book");
        for _ in 0..3 {
            assert_eq!(book.post_one().expect("post").committed, 1);
        }
        assert_eq!(book.post_batch().expect("batch").committed, BATCH_ENTRIES);
        assert_eq!(book.post_batch().expect("batch").committed, BATCH_ENTRIES);
        // The book lives on disk, and an existing directory is refused.
        drop(book);
        assert!(dir.join("store").exists());
        assert!(build(&dir, 42).is_err());
    }

    #[test]
    fn an_identical_retry_counts_no_work() {
        let mut book = build(&fresh("retry"), 7).expect("book");
        let intent = book.ledger.entry("post", 0).expect("intent");
        assert_eq!(book.post_intent(&intent).expect("post").committed, 1);
        // The kernel answers the identical retry from its record.
        assert_eq!(book.post_intent(&intent).expect("retry").committed, 0);
    }
}
