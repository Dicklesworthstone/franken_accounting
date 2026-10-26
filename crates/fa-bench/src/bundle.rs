//! FA-BENCH-11 (plan §17, fa-ykbp): bundle production and its offline
//! verification. A book of `entries` posted entries is checkpointed once;
//! each timed round produces the complete-prefix bundle with its signed
//! receipt and verifies it with the dependency-free `fa-verify`, as an
//! outsider would.
//!
//! The witness is the verifier's own count: the entries a bundle that
//! verified on every predicate carried (`Summary::entries`, which also
//! counts the book's control entries). A bundle that does not verify is an
//! error, never a sample.

use std::time::Instant;

use fa::book::{Book, BookKeys, Entropy};
use fa::{BundleRequest, BundleScope};
use fa_journal::{Capability, PostBatch};
use fa_model::{Id128, principal_vid};

use crate::BenchError;
use crate::rebuild::{Ledger, exec, spec};

/// Members per atomic batch while the book is built.
const BATCH: u64 = 256;

/// A checkpointed book ready for timed bundle rounds.
pub struct BundleBook {
    ledger: Ledger,
    produce: Capability,
    key: [u8; 32],
    /// Entries posted (control entries come on top).
    pub entries_posted: u64,
}

/// One timed production and verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bundled {
    pub elapsed_us: u64,
    /// Entries the verified bundle carried, as `fa-verify` counted them.
    pub entries_verified: u64,
}

/// Post `entries` entries and publish one checkpoint over them.
pub fn build(entries: u64, seed: u64) -> Result<BundleBook, BenchError> {
    if entries == 0 {
        return Err(BenchError::Execution(
            "the bundle workload needs at least one entry".into(),
        ));
    }
    let book_id = Id128(*b"FA-BENCH-BUNDLES");
    let (spec, usd) = spec(book_id, "Bench Bundle Book")?;
    let book = Book::create_memory(
        BookKeys::for_development(17),
        spec,
        Entropy::deterministic(17),
    )
    .map_err(exec)?;
    let mut ledger = Ledger::prepare(book, book_id, usd, seed)?;
    let mut next = 0u64;
    while next < entries {
        let end = (next + BATCH).min(entries);
        let members = (next..end)
            .map(|i| ledger.entry("bundle", i))
            .collect::<Result<Vec<_>, _>>()?;
        let batch = PostBatch::new(format!("bench:bundle-of:{next}").into_bytes(), members)
            .map_err(exec)?;
        ledger
            .book
            .post_batch(batch, &ledger.post)
            .map_err(exec)?
            .map_err(|r| exec(r.message))?;
        next = end;
    }
    let operator = principal_vid("operator");
    let witness = Capability::embedded(operator, &["witness"]).map_err(exec)?;
    ledger
        .book
        .checkpoint(operator, &witness)
        .map_err(exec)?
        .map_err(|r| exec(r.message))?;
    let key = ledger.book.checkpoint_public_key();
    let produce = Capability::embedded(operator, &["read", "produce"]).map_err(exec)?;
    Ok(BundleBook {
        ledger,
        produce,
        key,
        entries_posted: entries,
    })
}

impl BundleBook {
    /// Produce the complete-prefix bundle at the latest checkpoint and verify
    /// it offline with its receipt, timed together.
    pub fn produce_and_verify(&mut self) -> Result<Bundled, BenchError> {
        self.produce_and_verify_with(|_| {})
    }

    /// [`Self::produce_and_verify`], with `damage` applied to the bundle's
    /// bytes between production and verification (a planted negative).
    fn produce_and_verify_with(
        &mut self,
        damage: impl Fn(&mut Vec<u8>),
    ) -> Result<Bundled, BenchError> {
        let request = BundleRequest {
            scope: BundleScope::Prefix,
            balances: Vec::new(),
            inline_documents: false,
        };
        let start = Instant::now();
        let produced = self
            .ledger
            .book
            .produce_bundle(self.produce.holder(), &self.produce, None, &request)
            .map_err(exec)?
            .map_err(|r| exec(r.message))?
            .ok_or_else(|| exec("the book has no recorded checkpoint to prove against"))?;
        let mut bytes = produced.bundle.bytes;
        damage(&mut bytes);
        let report = fa_verify::verify_bundle(&bytes, &[self.key], Some(&produced.receipt));
        let elapsed_us = u64::try_from(start.elapsed().as_micros()).map_err(exec)?;
        match report {
            Ok(report) if report.verified() => Ok(Bundled {
                elapsed_us,
                entries_verified: report.summary.entries,
            }),
            Ok(_) => Err(BenchError::Execution(
                "the produced bundle did not verify offline; an unverified round is no sample"
                    .into(),
            )),
            Err(e) => Err(BenchError::Execution(format!(
                "the produced bundle did not verify offline ({e:?}); an unverified round is no sample"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verified_bundle_counts_every_posted_entry() {
        let mut book = build(300, 42).expect("book");
        let run = book.produce_and_verify().expect("bundle");
        // The 300 entries, plus the chart, periods and opens before them.
        assert!(run.entries_verified > 300, "{run:?}");
        assert_eq!(
            book.produce_and_verify().expect("again").entries_verified,
            run.entries_verified
        );
        assert!(build(0, 42).is_err());
    }

    #[test]
    fn a_bundle_that_does_not_verify_is_no_sample() {
        let mut book = build(20, 7).expect("book");
        // One flipped byte in the last entry's payload region.
        let err = book
            .produce_and_verify_with(|bytes| {
                let at = bytes.len() - 40;
                bytes[at] ^= 1;
            })
            .expect_err("a damaged bundle refuses");
        assert!(err.to_string().contains("did not verify"), "{err}");
        // Undamaged, the same book verifies.
        assert!(book.produce_and_verify().is_ok());
    }
}
