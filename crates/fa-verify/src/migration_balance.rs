//! Migration-aware balance proofs with payload-complete scope derivation.
//!
//! The v1 fields are followed by `list(open_leaf_index u64 || bytes(run_body))`.
//! In legacy v2 the record set is the union of selected candidate leaves and
//! EVERY MigrationControl leaf in the complete prefix. Each selected run
//! needs its Open body, in leaf order, whose length-framed domain digest
//! equals the Open's committed tie_out_digest and whose book/key derive
//! the named run identity. Unrelated run bodies are neither required nor accepted.
//!
//! V3 has the same field layout, but requires the payload of EVERY prefix
//! leaf, indexed exactly 0..leaf_count. Each envelope is rebuilt before it
//! can exclude that record from the fold or hide a lifecycle control. This
//! addresses fa-n6fh's balance attack: a root binds bytes, not correct indexing.
//! Legacy v2 is reported as `membership_only` when any prefix payload is
//! absent. V3 always establishes derivation as well as prefix membership.
//! Full-prefix disclosure and linear payload cost are explicit obligations;
//! callers lacking whole-book read authority must not produce this format.
//!
//! This proves the register visibility predicate, not the migration's economic
//! correctness, authorization, or trial-balance tie-out. Nothing reads current
//! database projections. Unknown bodies and malformed lifecycles fail closed.

use std::collections::{BTreeMap, BTreeSet};

use crate::balance::{
    Balance, BalanceClaim, CLASS_MIGRATION, SCOPE_MEMBERSHIP_ONLY, SCOPE_RECOMPUTATION,
    in_scope,
};
use crate::blake3::hash_parts;
use crate::codec::{DecodeError, Reader, Reason};
use crate::envelope::{LeafEnvelope, MAX_ENVELOPE_LIST, MAX_RECORD_BYTES, check_record};
use crate::proof::{Checkpoint, VerifyError, complete_prefix, open, read_envelopes, trusted};

pub const BALANCE_FORMAT_V2: &[u8] = b"fa:acc-balance-proof:v2";
pub const BALANCE_FORMAT_V3: &[u8] = b"fa:acc-balance-proof:v3";
/// Includes framing, all record payloads, and migration-body witnesses.
pub const MAX_BALANCE_PROOF_BYTES: usize = 64 * 1024 * 1024;

const CLASS_MIGRATION_CONTROL: u16 = 22;
const BODY_DOMAIN: &[u8] = b"fa:migration-run-body:v1";
const RUN_ID_DOMAIN: &[u8] = b"fa:vid:migration-run:v1";
const MAX_RUN_PERIODS: usize = 256;

// Migration bodies use fa-model's domain_digest, not the accumulator's
// raw-concatenation convention. Every part, including a fixed-width book
// id in derive_vid, has a u32 little-endian byte-length prefix. Inputs here
// have already been bounded by the decoder well below u32::MAX.
fn body_digest(body: &[u8]) -> [u8; 32] {
    let length = u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes();
    hash_parts(BODY_DOMAIN, &[&length, body])
}

fn run_identity(book: &[u8; 16], key: &[u8]) -> u128 {
    let book_length = 16u32.to_le_bytes();
    let key_length = u32::try_from(key.len()).unwrap_or(u32::MAX).to_le_bytes();
    let digest = hash_parts(RUN_ID_DOMAIN, &[&book_length, book, &key_length, key]);
    let mut low = [0u8; 16];
    low.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(low)
}

#[derive(Clone, Copy, Debug)]
enum Metadata {
    Ordinary,
    Chunk(u128),
    Control {
        run: u128,
        kind: u8,
        digest: [u8; 32],
        body_digest: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug)]
struct Policy {
    run: u128,
    opening_day: i32,
    counts_from: Option<i32>,
}

struct Run {
    open_index: u64,
    open_day: i32,
    digest: [u8; 32],
    terminal: Option<(u64, u8)>,
    policy: Option<Policy>,
}

fn scope_error(index: u64) -> VerifyError {
    VerifyError::RecordSet { index }
}

/// Verify v2 or v3 against an independently trusted checkpoint.
/// V3 authenticates EVERY envelope's derivation, including excluded leaves.
/// Both versions authenticate the supplied lifecycle controls and run bodies;
/// a partial-payload v2 result explicitly retains the weaker membership scope.
pub fn verify_balance(proof: &[u8], anchor: &Checkpoint) -> Result<Balance, VerifyError> {
    if proof.len() > MAX_BALANCE_PROOF_BYTES {
        return Err(VerifyError::Decode(DecodeError {
            offset: 0,
            what: "balance proof bytes",
            reason: Reason::TooLong {
                max: MAX_BALANCE_PROOF_BYTES,
                actual: proof.len(),
            },
        }));
    }
    let complete = Reader::new(proof).bytes(128, "proof.format")? == BALANCE_FORMAT_V3;
    let mut r = open(
        proof,
        if complete {
            BALANCE_FORMAT_V3
        } else {
            BALANCE_FORMAT_V2
        },
    )?;
    let checkpoint = trusted(Checkpoint::read(&mut r)?, anchor)?;
    let account = r.u128("balance.account")?;
    let unit = r.u32("balance.unit")?;
    let effective_through = if r.present("balance.effective_through")? {
        Some(r.i32("balance.effective_through")?)
    } else {
        None
    };
    let claim = BalanceClaim {
        account,
        unit,
        effective_through,
        debits: r.i128("balance.debits")?,
        credits: r.i128("balance.credits")?,
    };
    let raw = read_envelopes(&mut r)?;
    let n = r.count(raw.len(), 16, "proof.records")?;
    let mut records = Vec::with_capacity(n);
    for _ in 0..n {
        let index = r.u64("record.leaf_index")?;
        let len = usize::try_from(r.u32("record.proposal_len")?).unwrap_or(usize::MAX);
        records.push((index, len, r.bytes(MAX_RECORD_BYTES, "record.payload")?));
    }
    let n = r.count(raw.len(), 12, "proof.run_bodies")?;
    let mut bodies = Vec::with_capacity(n);
    for _ in 0..n {
        bodies.push((
            r.u64("run_body.open_leaf_index")?,
            r.bytes(MAX_RECORD_BYTES, "run_body.bytes")?,
        ));
    }
    r.finish("migration balance proof")?;

    let envelopes = complete_prefix(&raw, &checkpoint)?;
    let expected: Vec<_> = envelopes
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            complete
                || e.class == CLASS_MIGRATION_CONTROL
                || in_scope(e, claim.account, claim.unit, claim.effective_through)
        })
        .map(|(i, e)| (u64::try_from(i).unwrap_or(u64::MAX), e))
        .collect();
    for (position, (want, _)) in expected.iter().enumerate() {
        match records.get(position) {
            Some((got, _, _)) if got == want => {}
            Some((got, _, _)) => return Err(scope_error((*want).min(*got))),
            None => return Err(scope_error(*want)),
        }
    }
    if let Some((extra, _, _)) = records.get(expected.len()) {
        return Err(scope_error(*extra));
    }

    let mut runs: BTreeMap<u128, Run> = BTreeMap::new();
    let mut opens = Vec::new();
    let mut needed_runs = BTreeSet::new();
    let mut verified = Vec::with_capacity(records.len());
    for ((index, len, payload), (_, envelope)) in records.iter().zip(&expected) {
        let legs = check_record(envelope, payload, *len).map_err(VerifyError::Record)?;
        // In v3, even a Pending/undated/unrelated/future leaf reaches the
        // derivation check above. Only authenticated selectors may exclude it.
        // Do not interpret unrelated control payloads as migration metadata,
        // or disclose unrelated run bodies just because their chunks exist.
        if envelope.class != CLASS_MIGRATION_CONTROL
            && !in_scope(envelope, claim.account, claim.unit, claim.effective_through)
        {
            continue;
        }
        let metadata = metadata(envelope, &payload[..*len], *index)?;
        if let Metadata::Chunk(run) = metadata {
            needed_runs.insert(run);
        }
        if let Metadata::Control {
            run,
            kind,
            digest,
            body_digest,
        } = metadata
        {
            if kind == 0 {
                if runs.contains_key(&run) {
                    return Err(scope_error(*index));
                }
                let open_day = envelope.effective_day.ok_or_else(|| scope_error(*index))?;
                runs.insert(
                    run,
                    Run {
                        open_index: *index,
                        open_day,
                        digest,
                        terminal: None,
                        policy: None,
                    },
                );
                opens.push((*index, run));
            } else {
                let state = runs.get_mut(&run).ok_or_else(|| scope_error(*index))?;
                if state.terminal.is_some()
                    || *index <= state.open_index
                    || body_digest != state.digest
                {
                    return Err(scope_error(*index));
                }
                state.terminal = Some((*index, kind));
            }
        }
        verified.push((*index, *envelope, metadata, legs));
    }

    // Do not disclose an unrelated run's legacy trial balances. Controls
    // authenticate lifecycle completeness; bodies are required only for
    // runs named by selected migration candidates (including invisible ones).
    opens.retain(|(_, run)| needed_runs.contains(run));
    for (position, (open_index, run)) in opens.iter().enumerate() {
        let Some((got, bytes)) = bodies.get(position) else {
            return Err(scope_error(*open_index));
        };
        if got != open_index {
            return Err(scope_error((*got).min(*open_index)));
        }
        let state = runs.get_mut(run).ok_or_else(|| scope_error(*open_index))?;
        if body_digest(bytes) != state.digest {
            return Err(VerifyError::Record(crate::envelope::RecordError::Digest {
                which: "migration.run_body",
            }));
        }
        let policy = policy(bytes, &checkpoint.book_id)?;
        if policy.run != *run || policy.opening_day != state.open_day {
            return Err(scope_error(*open_index));
        }
        state.policy = Some(policy);
    }
    if let Some((extra, _)) = bodies.get(opens.len()) {
        return Err(scope_error(*extra));
    }

    let (mut debits, mut credits) = (0i128, 0i128);
    let mut contributing = Vec::new();
    for (index, envelope, metadata, legs) in &verified {
        let visible = match metadata {
            Metadata::Control { .. } => false,
            Metadata::Ordinary => true,
            Metadata::Chunk(run) => {
                let state = runs.get(run).ok_or_else(|| scope_error(*index))?;
                if *index <= state.open_index
                    || state
                        .terminal
                        .is_some_and(|(terminal, _)| *index >= terminal)
                {
                    return Err(scope_error(*index));
                }
                let policy = state.policy.ok_or_else(|| scope_error(state.open_index))?;
                state.terminal.is_some_and(|(_, kind)| kind == 1)
                    && policy.counts_from.is_none_or(|day| {
                        envelope
                            .effective_day
                            .is_some_and(|effective| effective >= day)
                    })
            }
        };
        if !visible {
            continue;
        }
        contributing.push(*index);
        for leg in legs
            .iter()
            .filter(|leg| leg.account == claim.account && leg.unit == claim.unit)
        {
            if leg.mantissa < 0 {
                return Err(VerifyError::Arithmetic);
            }
            let column = if leg.debit { &mut debits } else { &mut credits };
            *column = column
                .checked_add(leg.mantissa)
                .ok_or(VerifyError::Arithmetic)?;
        }
    }
    if (debits, credits) != (claim.debits, claim.credits) {
        return Err(VerifyError::Claim { debits, credits });
    }
    Ok(Balance {
        scope: if records.len() == envelopes.len() {
            SCOPE_RECOMPUTATION
        } else {
            SCOPE_MEMBERSHIP_ONLY
        },
        checkpoint,
        claim,
        contributing,
    })
}

fn erasable(r: &mut Reader<'_>) -> Result<(), DecodeError> {
    r.fixed::<32>("erasable.digest")?;
    if r.present("erasable.subject")? {
        r.u128("erasable.subject")?;
    }
    r.fixed::<24>("erasable.nonce")?;
    r.bytes(MAX_RECORD_BYTES, "erasable.ciphertext")?;
    Ok(())
}

// Decode only the fields needed for visibility, AFTER check_record binds the
// full payload and all envelope fields. No policy is taken from an unbound
// suffix or a producer-provided projection. The remaining origin/proposal
// fields are digest-covered but irrelevant to this predicate.
fn metadata(e: &LeafEnvelope, proposal: &[u8], index: u64) -> Result<Metadata, VerifyError> {
    let mut r = Reader::new(proposal);
    r.u16("entry.major")?;
    r.u16("entry.minor")?;
    r.fixed::<16>("entry.book")?;
    r.fixed::<16>("entry.branch")?;
    r.u16("entry.class")?;
    r.i32("entry.effective_date")?;
    if r.present("entry.document_date")? {
        r.i32("entry.document_date")?;
    }
    erasable(&mut r)?;
    if r.present("entry.period")? {
        r.bytes(MAX_RECORD_BYTES, "entry.period.calendar")?;
        r.bytes(MAX_RECORD_BYTES, "entry.period.code")?;
    }
    let legs = r.count(MAX_ENVELOPE_LIST, 47, "entry.legs")?;
    for _ in 0..legs {
        r.fixed::<37>("leg.side_account_amount")?;
        if r.present("leg.base_amount")? {
            r.fixed::<20>("leg.base_amount")?;
        }
        let dims = r.count(MAX_ENVELOPE_LIST, 20, "leg.dimensions")?;
        for _ in 0..dims {
            r.fixed::<20>("leg.dimension")?;
        }
        if r.present("leg.memo")? {
            erasable(&mut r)?;
        }
        let settles = r.count(MAX_ENVELOPE_LIST, 70, "leg.settles")?;
        for _ in 0..settles {
            r.fixed::<70>("leg.settlement")?;
        }
    }
    let control = if r.present("entry.control")? {
        if e.class != CLASS_MIGRATION_CONTROL || legs != 0 || r.u8("control.tag")? != 10 {
            return Err(scope_error(index));
        }
        let run = r.u128("control.run_ref")?;
        let kind = r.u8("control.kind")?;
        if kind > 2 {
            return Err(scope_error(index));
        }
        Some((run, kind, r.fixed::<32>("control.tie_out_digest")?))
    } else {
        None
    };
    let totals = r.count(MAX_ENVELOPE_LIST, 36, "entry.unit_totals")?;
    for _ in 0..totals {
        r.fixed::<36>("entry.unit_total")?;
    }
    if r.present("entry.base_totals")? {
        r.fixed::<68>("entry.base_totals")?;
        let rates = r.count(MAX_ENVELOPE_LIST, 32, "entry.rate_docs")?;
        for _ in 0..rates {
            r.fixed::<32>("entry.rate_doc")?;
        }
        if r.present("entry.residual")? {
            r.fixed::<22>("entry.residual")?;
        }
    }
    r.bytes(MAX_RECORD_BYTES, "entry.idempotency_key")?;
    let origin = r.u8("entry.origin")?;
    if e.class == CLASS_MIGRATION_CONTROL {
        let (run, kind, digest) = control.ok_or_else(|| scope_error(index))?;
        if origin != 3 || r.u16("origin.control_kind")? != 9 {
            return Err(scope_error(index));
        }
        let body_digest = r.fixed::<32>("origin.spec_body_digest")?;
        if kind == 0 && body_digest != digest {
            return Err(scope_error(index));
        }
        return Ok(Metadata::Control {
            run,
            kind,
            digest,
            body_digest,
        });
    }
    if origin == 2 {
        if e.class != CLASS_MIGRATION {
            return Err(scope_error(index));
        }
        return Ok(Metadata::Chunk(r.u128("origin.run_ref")?));
    }
    if e.class == CLASS_MIGRATION || !matches!(origin, 0 | 1 | 4 | 5) {
        return Err(scope_error(index));
    }
    Ok(Metadata::Ordinary)
}

fn lines(r: &mut Reader<'_>) -> Result<(), DecodeError> {
    let count = r.count(MAX_ENVELOPE_LIST, 24, "run.lines")?;
    for _ in 0..count {
        r.bytes(64, "run.line.account")?;
        r.u32("run.line.unit")?;
        r.i128("run.line.mantissa")?;
    }
    Ok(())
}

fn policy(bytes: &[u8], book: &[u8; 16]) -> Result<Policy, VerifyError> {
    let mut r = Reader::new(bytes);
    let version = r.u16("run.version")?;
    if version != 1 {
        return Err(VerifyError::Decode(
            r.error("run.version", Reason::BadTag(version.to_le_bytes()[0])),
        ));
    }
    if r.fixed::<16>("run.book")? != *book {
        return Err(VerifyError::Coordinate);
    }
    let key = r.bytes(64, "run.key")?;
    let run = run_identity(book, key);
    r.bytes(MAX_RECORD_BYTES, "run.source_system")?;
    let mode = r.u8("run.mode")?;
    if mode > 2 {
        return Err(VerifyError::Decode(
            r.error("run.mode", Reason::BadTag(mode)),
        ));
    }
    r.fixed::<32>("run.trial_balance")?;
    let opening_day = r.i32("run.opening_date")?;
    lines(&mut r)?;
    if mode != 0 {
        let periods = r.count(MAX_RUN_PERIODS, 40, "run.periods")?;
        for _ in 0..periods {
            r.bytes(64, "run.period.code")?;
            r.fixed::<32>("run.period.trial_balance")?;
            lines(&mut r)?;
        }
    }
    let sole = if mode == 2 {
        lines(&mut r)?;
        r.present("run.sole_opening_source")?
    } else {
        false
    };
    r.finish("migration run body")?;
    Ok(Policy {
        run,
        opening_day,
        counts_from: (mode == 2 && !sole).then_some(opening_day),
    })
}

#[cfg(test)]
mod tests {
    mod complete_tests;

    use super::*;
    use crate::codec::Writer;
    use crate::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
    use crate::tree::{leaf_hash, root_of};

    // Pinned in fa-model ids::migration_identities_are_pinned for book [1;16]
    // and key "go-live". This is data, not a dependency on producer code.
    const RUN: u128 = 0x234a_61ec_52cd_c6a7_442d_0c1f_8c35_b825;

    // Independent canonical wire fixtures. These test the offline predicate;
    // they do not claim that the kernel admitted the synthetic accounting.
    #[derive(Clone, Copy)]
    enum Kind {
        Ordinary,
        Chunk(u128),
        Control(u128, u8, [u8; 32]),
    }

    struct Record {
        envelope: LeafEnvelope,
        len: usize,
        payload: Vec<u8>,
    }

    fn sealed(w: &mut Writer) {
        w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
    }

    fn record(kind: Kind, seq: u64, day: i32) -> Record {
        let class = match kind {
            Kind::Ordinary => 1,
            Kind::Chunk(_) => CLASS_MIGRATION,
            Kind::Control(..) => CLASS_MIGRATION_CONTROL,
        };
        let control = matches!(kind, Kind::Control(..));
        let mut w = Writer::default();
        w.u16(1)
            .u16(0)
            .fixed(&[1; 16])
            .fixed(&[0; 16])
            .u16(class)
            .i32(day)
            .u8(0);
        sealed(&mut w);
        w.u8(0).count(if control { 0 } else { 2 });
        if !control {
            for (side, account) in [(0, 10), (1, 20)] {
                w.u8(side)
                    .u128(account)
                    .u32(1)
                    .i128(5000)
                    .u8(0)
                    .count(0)
                    .u8(0)
                    .count(0);
            }
        }
        if let Kind::Control(run, kind, digest) = kind {
            // Open ties to the body; terminal tie-outs commit the chunk set.
            // The origin below retains the same body digest at every phase.
            let tie_out = if kind == 0 { digest } else { [9; 32] };
            w.u8(1).u8(10).u128(run).u8(kind).fixed(&tie_out);
        } else {
            w.u8(0);
        }
        w.count(if control { 0 } else { 1 });
        if !control {
            w.u32(1).i128(5000).i128(5000);
        }
        w.u8(0).bytes(&seq.to_le_bytes());
        match kind {
            Kind::Ordinary => {
                w.u8(0).fixed(&[0; 32]).u16(1);
            }
            Kind::Control(_, _, digest) => {
                w.u8(3).u16(9).fixed(&digest);
            }
            Kind::Chunk(run) => {
                w.u8(2).u128(run).bytes(b"legacy");
                sealed(&mut w);
                w.u8(0).u8(0).u8(0).fixed(&[0; 32]);
            }
        }
        w.u128(1).u8(0).count(0).count(0).u8(0).count(0).count(0);
        let len = w.buf.len();
        let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
        let envelope = [0u8; 5]; // no plan certificate and no approvals
        let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &envelope]);
        w.fixed(&envelope).fixed(&proposal_digest).fixed(&digest);
        let envelope = envelope_of_entry(&w.buf, len, seq, 0).unwrap();
        Record {
            envelope,
            len,
            payload: w.buf,
        }
    }

    fn body(mode: u8, sole: bool) -> Vec<u8> {
        let mut w = Writer::default();
        w.u16(1)
            .fixed(&[1; 16])
            .bytes(b"go-live")
            .bytes(b"legacy")
            .u8(mode)
            .fixed(&[0; 32])
            .i32(100)
            .count(0);
        if mode != 0 {
            w.count(0);
        }
        if mode == 2 {
            w.count(0).u8(u8::from(sole));
        }
        w.buf
    }

    fn history(body: &[u8], day: i32, terminal: Option<u8>) -> Vec<Record> {
        let digest = body_digest(body);
        let mut records = vec![
            record(Kind::Control(RUN, 0, digest), 1, 100),
            record(Kind::Chunk(RUN), 2, day),
        ];
        if let Some(kind) = terminal {
            records.push(record(Kind::Control(RUN, kind, digest), 3, 100));
        }
        records
    }

    fn proof(
        records: &[Record],
        bodies: &[(u64, Vec<u8>)],
        debits: i128,
        through: Option<i32>,
        omit: Option<usize>,
    ) -> (Vec<u8>, Checkpoint) {
        proof_format(records, bodies, debits, through, omit, BALANCE_FORMAT_V2)
    }

    fn proof_format(
        records: &[Record],
        bodies: &[(u64, Vec<u8>)],
        debits: i128,
        through: Option<i32>,
        omit: Option<usize>,
        format: &[u8],
    ) -> (Vec<u8>, Checkpoint) {
        let hashes: Vec<_> = records
            .iter()
            .map(|r| leaf_hash(&r.envelope.encode()))
            .collect();
        let checkpoint = Checkpoint {
            book_id: [1; 16],
            branch_id: [0; 16],
            through_seq: records.last().map_or(0, |r| r.envelope.commit_seq),
            leaf_count: u64::try_from(records.len()).unwrap(),
            root: root_of(&hashes),
        };
        let selected: Vec<_> = records
            .iter()
            .enumerate()
            .filter(|(i, r)| {
                Some(*i) != omit
                    && (format == BALANCE_FORMAT_V3
                        || r.envelope.class == CLASS_MIGRATION_CONTROL
                        || in_scope(&r.envelope, 10, 1, through))
            })
            .collect();
        let mut w = Writer::default();
        w.bytes(format)
            .fixed(&checkpoint.encode())
            .u128(10)
            .u32(1);
        match through {
            Some(day) => {
                w.u8(1).i32(day);
            }
            None => {
                w.u8(0);
            }
        }
        w.i128(debits).i128(0).count(records.len());
        for r in records {
            w.bytes(&r.envelope.encode());
        }
        w.count(selected.len());
        for (index, r) in selected {
            w.u64(u64::try_from(index).unwrap())
                .u32(u32::try_from(r.len).unwrap())
                .bytes(&r.payload);
        }
        w.count(bodies.len());
        for (index, body) in bodies {
            w.u64(*index).bytes(body);
        }
        (w.buf, checkpoint)
    }

    #[test]
    fn open_abandoned_and_finalized_runs_have_different_proven_balances() {
        let body = body(0, false);
        for (terminal, expected) in [(None, 0), (Some(2), 0), (Some(1), 5000)] {
            let records = history(&body, 100, terminal);
            let witnesses = [(0, body.clone())];
            let (bytes, anchor) = proof(&records, &witnesses, expected, None, None);
            let report = super::verify_balance(&bytes, &anchor).unwrap();
            assert_eq!(report.claim.debits, expected);
            assert_eq!(
                report.contributing,
                if expected == 0 { vec![] } else { vec![1] }
            );
            let (wrong, anchor) = proof(&records, &witnesses, 5000 - expected, None, None);
            assert_eq!(
                super::verify_balance(&wrong, &anchor),
                Err(VerifyError::Claim {
                    debits: expected,
                    credits: 0,
                })
            );
        }
    }

    #[test]
    fn every_migration_mode_obeys_its_historical_visibility_and_inclusive_cutoff() {
        for (mode, sole, day, expected) in [
            (0, false, 90, 5000),
            (1, false, 90, 5000),
            (2, false, 90, 0),
            (2, true, 90, 5000),
            (2, false, 100, 5000),
        ] {
            let body = body(mode, sole);
            let records = history(&body, day, Some(1));
            let (bytes, anchor) = proof(&records, &[(0, body)], expected, Some(day), None);
            assert_eq!(
                super::verify_balance(&bytes, &anchor).unwrap().claim.debits,
                expected
            );
            let (earlier, anchor) = proof(&records, &[], 0, Some(day - 1), None);
            assert!(
                super::verify_balance(&earlier, &anchor)
                    .unwrap()
                    .contributing
                    .is_empty()
            );
        }
    }

    #[test]
    fn controls_and_bodies_cannot_be_omitted_duplicated_or_substituted() {
        let body = body(2, false);
        let records = history(&body, 90, Some(1));
        for omit in [0, 1, 2] {
            let (bytes, anchor) = proof(&records, &[(0, body.clone())], 0, None, Some(omit));
            assert!(matches!(
                super::verify_balance(&bytes, &anchor),
                Err(VerifyError::RecordSet { .. })
            ));
        }
        for bodies in [
            vec![],
            vec![(0, body.clone()), (0, body.clone())],
            vec![(1, body.clone())],
        ] {
            let (bytes, anchor) = proof(&records, &bodies, 0, None, None);
            assert!(matches!(
                super::verify_balance(&bytes, &anchor),
                Err(VerifyError::RecordSet { .. })
            ));
        }
        let mut substituted = body;
        *substituted.last_mut().unwrap() = 1; // claiming sole source would count history
        let (bytes, anchor) = proof(&records, &[(0, substituted)], 5000, None, None);
        assert!(matches!(
            super::verify_balance(&bytes, &anchor),
            Err(VerifyError::Record(_))
        ));
    }

    #[test]
    fn malformed_lifecycles_never_manufacture_visibility() {
        let body = body(0, false);
        let digest = body_digest(&body);
        let cases = [
            vec![record(Kind::Control(RUN, 1, digest), 1, 100)],
            vec![
                record(Kind::Control(RUN, 0, digest), 1, 100),
                record(Kind::Control(RUN, 0, digest), 2, 100),
            ],
            vec![
                record(Kind::Control(RUN, 0, digest), 1, 100),
                record(Kind::Control(RUN, 1, digest), 2, 100),
                record(Kind::Chunk(RUN), 3, 100),
            ],
            vec![
                record(Kind::Chunk(RUN), 1, 100),
                record(Kind::Control(RUN, 0, digest), 2, 100),
            ],
            vec![
                record(Kind::Control(RUN, 0, digest), 1, 100),
                record(Kind::Control(RUN, 2, digest), 2, 100),
                record(Kind::Control(RUN, 1, digest), 3, 100),
            ],
        ];
        for records in cases {
            let open_index = records
                .iter()
                .position(|r| r.envelope.class == CLASS_MIGRATION_CONTROL)
                .unwrap_or(0);
            let witnesses = [(u64::try_from(open_index).unwrap(), body.clone())];
            let (bytes, anchor) = proof(&records, &witnesses, 0, None, None);
            assert!(matches!(
                super::verify_balance(&bytes, &anchor),
                Err(VerifyError::RecordSet { .. })
            ));
        }
    }

    #[test]
    fn ordinary_and_empty_v2_prefixes_work_without_run_metadata() {
        for records in [
            vec![],
            vec![record(Kind::Ordinary, 1, 100)],
            vec![
                record(Kind::Control(RUN, 0, [9; 32]), 1, 100),
                record(Kind::Ordinary, 2, 100),
            ],
        ] {
            let amount = if records.is_empty() { 0 } else { 5000 };
            let (bytes, anchor) = proof(&records, &[], amount, None, None);
            assert_eq!(
                super::verify_balance(&bytes, &anchor).unwrap().claim.debits,
                amount
            );
        }
    }

    #[test]
    fn migration_hash_transcripts_are_length_framed_and_run_identity_is_pinned() {
        assert_eq!(run_identity(&[1; 16], b"go-live"), RUN);
        for body in [
            body(0, false),
            body(1, false),
            body(2, false),
            body(2, true),
        ] {
            let mut transcript = BODY_DOMAIN.to_vec();
            transcript.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            transcript.extend_from_slice(&body);
            assert_eq!(body_digest(&body), crate::blake3::hash(&transcript));
            assert_ne!(
                body_digest(&body),
                hash_parts(BODY_DOMAIN, &[&body]),
                "the accumulator's unframed transcript is not a RunBody digest"
            );
        }
    }

    #[test]
    fn run_identity_and_terminal_policy_cannot_be_rebound_under_authentic_records() {
        let body = body(0, false);
        let digest = body_digest(&body);
        let wrong_run = RUN ^ 1;
        let wrong_identity = vec![
            record(Kind::Control(wrong_run, 0, digest), 1, 100),
            record(Kind::Chunk(wrong_run), 2, 100),
            record(Kind::Control(wrong_run, 1, digest), 3, 100),
        ];
        let (bytes, anchor) = proof(&wrong_identity, &[(0, body.clone())], 5000, None, None);
        assert_eq!(
            super::verify_balance(&bytes, &anchor),
            Err(VerifyError::RecordSet { index: 0 })
        );
        let mut records = history(&body, 100, Some(1));
        records[2] = record(Kind::Control(RUN, 1, [8; 32]), 3, 100);
        let (bytes, anchor) = proof(&records, &[(0, body)], 5000, None, None);
        assert_eq!(
            super::verify_balance(&bytes, &anchor),
            Err(VerifyError::RecordSet { index: 2 })
        );
    }
}
