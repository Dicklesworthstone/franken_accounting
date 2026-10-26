//! The first real §17 workload (plan §17, FA-BENCH-06, fa-ykbp): a full
//! register rebuild from the journal, over a book posted at a stated scale.
//!
//! The book holds `legs` legs, two per entry, effective across FY2026's
//! twelve monthly periods and posted in atomic batches. Its registers are
//! first maintained by the incremental maintainer, so every timed rebuild is
//! checked digest-equal to what maintenance holds; a rebuild that differs is
//! an error, never a sample. The work witness is the engine's own count: the
//! legs each period's rebuild added to its cells (`Advance::legs_folded`).
//!
//! [`Ledger`] is the book every write-path workload shares: the demo chart,
//! FY2026's twelve periods open, one cited document, and a seeded stream of
//! balanced two-leg entries.

use std::time::Instant;

use fa::book::{Book, BookKeys, Entropy};
use fa_demo::us_gaap_smb_accounts;
use fa_journal::{BookSpec, Capability, Document, PostBatch, PostIntent, TimeZonePolicy};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, LegPayload, Oid,
    account_vid, domain_digest, principal_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::VId;

use crate::BenchError;

/// Members per atomic batch while the book is built.
const BATCH: u64 = 256;
/// The (debit, credit) account pairs entries cycle through.
const PAIRS: [(&str, &str); 3] = [("1010", "4000"), ("5000", "1010"), ("6000", "1010")];

pub(crate) fn exec(e: impl std::fmt::Display) -> BenchError {
    BenchError::Execution(e.to_string())
}

/// The spec of a bench book named `name`, with identity `book_id`.
pub(crate) fn spec(book_id: Id128, name: &str) -> Result<(BookSpec, UnitId), BenchError> {
    let units = UnitRegistry::embedded().map_err(exec)?;
    let usd = units
        .lookup("USD")
        .ok_or_else(|| BenchError::Execution("missing USD".into()))?;
    let calendar = FiscalCalendar::monthly("US-FY", 1, 1).map_err(|e| exec(format!("{e:?}")))?;
    let opening = DateDay::from_ymd(2026, 1, 1).map_err(|e| exec(format!("{e:?}")))?;
    Ok((
        BookSpec {
            book_id,
            name: name.into(),
            base_unit: usd,
            calendar,
            time_zone_policy: Some(TimeZonePolicy::Utc),
            entities: Vec::new(),
            opening_date: Some(opening),
        },
        usd,
    ))
}

/// A bench book ready to post: the demo chart, FY2026's twelve periods open,
/// one cited document, and a seeded stream of balanced two-leg entries.
pub(crate) struct Ledger {
    pub(crate) book: Book,
    pub(crate) periods: Vec<String>,
    pub(crate) post: Capability,
    book_id: Id128,
    usd: UnitId,
    operator: VId,
    evidence: EvidenceRef,
    description: Erasable<String>,
    state: u64,
}

impl Ledger {
    /// Prepare `book` (created from [`spec`] with `book_id` and `usd`).
    pub(crate) fn prepare(
        mut book: Book,
        book_id: Id128,
        usd: UnitId,
        seed: u64,
    ) -> Result<Self, BenchError> {
        let opening = DateDay::from_ymd(2026, 1, 1).map_err(|e| exec(format!("{e:?}")))?;
        let operator = principal_vid("operator");
        let controller = principal_vid("controller");
        let schema = Capability::embedded(operator, &["schema_change"]).map_err(exec)?;
        book.install_chart(
            &us_gaap_smb_accounts(usd),
            operator,
            opening,
            b"bench:chart",
            &schema,
        )
        .map_err(exec)?
        .map_err(|r| exec(r.message))?;
        book.create_periods(2026, operator, &schema)
            .map_err(exec)?
            .map_err(|r| exec(r.to_string()))?;
        let close = Capability::embedded(controller, &["close"]).map_err(exec)?;
        let periods: Vec<String> = (1..=12).map(|m| format!("FY2026-P{m:02}")).collect();
        for period in &periods {
            book.transition_period(
                period,
                PeriodTransition::Open,
                controller,
                1,
                format!("bench:open:{period}").as_bytes(),
                &close,
            )
            .map_err(exec)?
            .map_err(|r| exec(r.message))?;
        }
        let document = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: operator,
            bytes: b"bench-source-ledger".to_vec(),
        };
        book.add_document(&document)
            .map_err(exec)?
            .map_err(|r| exec(r.message))?;
        let evidence = document.evidence_ref(1);
        let description = book.seal_text("bench entry").map_err(exec)?;
        let post = Capability::embedded(operator, &["post"]).map_err(exec)?;
        Ok(Self {
            book,
            periods,
            post,
            book_id,
            usd,
            operator,
            evidence,
            description,
            state: seed,
        })
    }

    /// The `i`th entry of the stream: a balanced two-leg Original, effective
    /// in month `i mod 12`, with a seeded amount and the key `bench:<tag>:<i>`.
    pub(crate) fn entry(&mut self, tag: &str, i: u64) -> Result<PostIntent, BenchError> {
        // splitmix64 step: amounts are seeded, not constant.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let cents = 100 + i128::from((z ^ (z >> 31)) % 9_999_900);
        let month = u8::try_from(i % 12).map_err(exec)? + 1;
        let day = u8::try_from((i / 12) % 28).map_err(exec)? + 1;
        let effective = DateDay::from_ymd(2026, month, day).map_err(|e| exec(format!("{e:?}")))?;
        let (debit, credit) = PAIRS[usize::try_from(i % 3).map_err(exec)?];
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(self.book_id, debit),
                Amount::new(self.usd, cents),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(self.book_id, credit),
                Amount::new(self.usd, cents),
            ),
        ];
        let key = format!("bench:{tag}:{i}").into_bytes();
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id: self.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: effective,
            document_date: Some(effective),
            description: self.description.clone(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).map_err(exec)?,
            legs,
            control: None,
            base_totals: None,
            origin: EntryOrigin::Intent {
                intent_oid: Oid(domain_digest(b"fa:intent:v1", &[&key])),
                intent_kind: 1,
            },
            idempotency_key: key,
            principal_ref: self.operator,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        PostIntent::new(proposal, Vec::new()).map_err(exec)
    }
}

/// A book posted for the rebuild workload, with its maintained registers.
pub struct RebuildBook {
    ledger: Ledger,
    /// Each period's maintained fold digest, in period order.
    maintained: Vec<[u8; 32]>,
    /// Legs posted, two per entry.
    pub legs_posted: u64,
}

/// One timed full rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rebuilt {
    /// Wall time of the rebuild of every period, in microseconds.
    pub elapsed_us: u64,
    /// Legs the rebuild folded, summed over periods, as the engine counted.
    pub legs_folded: u64,
}

/// Post `legs` legs (a positive even count) across FY2026's twelve periods
/// and maintain every period's registers. Amounts come from `seed`.
pub fn build(legs: u64, seed: u64) -> Result<RebuildBook, BenchError> {
    if legs == 0 || !legs.is_multiple_of(2) {
        return Err(BenchError::Execution(format!(
            "the rebuild workload posts two legs per entry; {legs} legs is not a positive even count"
        )));
    }
    let book_id = Id128(*b"FA-BENCH-REBUILD");
    let (spec, usd) = spec(book_id, "Bench Rebuild Book")?;
    let book = Book::create_memory(
        BookKeys::for_development(11),
        spec,
        Entropy::deterministic(11),
    )
    .map_err(exec)?;
    let mut ledger = Ledger::prepare(book, book_id, usd, seed)?;
    let entries = legs / 2;
    let mut next = 0u64;
    while next < entries {
        let end = (next + BATCH).min(entries);
        let members = (next..end)
            .map(|i| ledger.entry("rebuild", i))
            .collect::<Result<Vec<_>, _>>()?;
        let batch = PostBatch::new(format!("bench:rebuild:batch:{next}").into_bytes(), members)
            .map_err(exec)?;
        ledger
            .book
            .post_batch(batch, &ledger.post)
            .map_err(exec)?
            .map_err(|r| exec(r.message))?;
        next = end;
    }

    let mut maintained = Vec::with_capacity(ledger.periods.len());
    for period in &ledger.periods {
        let advance = ledger.book.advance_registers(period).map_err(exec)?;
        maintained.push(advance.fold.fold_digest);
    }
    Ok(RebuildBook {
        ledger,
        maintained,
        legs_posted: legs,
    })
}

impl RebuildBook {
    /// Rebuild every period's registers from the journal, timed, and check
    /// each refold digest-equal to the maintained registers.
    pub fn rebuild(&mut self) -> Result<Rebuilt, BenchError> {
        let start = Instant::now();
        let mut advances = Vec::with_capacity(self.ledger.periods.len());
        for period in &self.ledger.periods {
            advances.push(self.ledger.book.rebuild_registers(period).map_err(exec)?);
        }
        let elapsed_us = u64::try_from(start.elapsed().as_micros()).map_err(exec)?;
        let mut legs_folded = 0u64;
        for ((advance, period), maintained) in advances
            .iter()
            .zip(&self.ledger.periods)
            .zip(&self.maintained)
        {
            if !advance.rebuilt || advance.fold.fold_digest != *maintained {
                return Err(BenchError::Execution(format!(
                    "the rebuilt registers of {period} are not digest-equal to the maintained ones; a drifting rebuild is no sample"
                )));
            }
            legs_folded = legs_folded
                .checked_add(advance.legs_folded)
                .ok_or_else(|| exec("legs folded overflowed u64"))?;
        }
        Ok(Rebuilt {
            elapsed_us,
            legs_folded,
        })
    }

    /// The maintained digests, for a planted negative to disturb.
    #[cfg(test)]
    pub(crate) fn maintained_mut(&mut self) -> &mut Vec<[u8; 32]> {
        &mut self.maintained
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuild_witness_counts_every_posted_leg() {
        // 600 legs: 300 entries, two batches, 25 per period.
        let mut book = build(600, 42).expect("book");
        for _ in 0..2 {
            let run = book.rebuild().expect("rebuild");
            assert_eq!(run.legs_folded, 600);
        }
        assert!(build(601, 42).is_err());
        assert!(build(0, 42).is_err());
    }

    #[test]
    fn a_rebuild_unequal_to_maintenance_is_no_sample() {
        let mut book = build(48, 7).expect("book");
        book.maintained_mut()[3][0] ^= 1;
        let err = book.rebuild().expect_err("a drifted digest refuses");
        assert!(
            err.to_string().contains("FY2026-P04") && err.to_string().contains("not digest-equal"),
            "{err}"
        );
    }
}
