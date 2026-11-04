//! Independent, exact replay of the original round-amount procedure.
//!
//! The complete journal prefix supplies the population; native read witnesses
//! and the producer's findings supply no arithmetic. This first profile accepts
//! only `jet.round_amounts` v1 without an effective-date cutoff or input handles.
//! It proves the statistical computation and decision-card encoding, not fraud,
//! approval admission, policy activation, or authenticity of source documents.

use std::collections::{BTreeMap, BTreeSet};

use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, failed, text};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};

const FORMAT: &[u8] = b"fa:procedure-certificate:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:procedure-output:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:procedure-certificate-digest:v1";
const ID: &str = "jet.round_amounts";
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
const MAX_FINDINGS: usize = 100_000;
const MAX_CITES: usize = 4096;

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub registry_digest: [u8; 32],
    pub output: &'a [u8],
    pub digest: [u8; 32],
    book: [u8; 16],
    known_at: u64,
    round_power: u32,
}

/// One independently reproduced round-amount finding. The statistic counts
/// these leg ordinals, with scale zero and `VerifiedProcedure.live_legs` as its
/// population. The entry citation precedes the ordered leg citations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRoundAmountFinding {
    pub entry: u128,
    /// The registered severity tag: 1 (Low) or 2 (Medium).
    pub severity: u8,
    pub round_legs: Vec<u16>,
    pub narrative: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProcedure {
    pub procedure: String,
    pub version: u16,
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub round_power: u32,
    /// Every visible entry, including controls, reservations and reversals.
    pub population: u64,
    /// Work and statistic populations are the net live posting stream.
    pub live_entries: u64,
    pub live_legs: u64,
    pub findings: Vec<VerifiedRoundAmountFinding>,
    pub parameters_digest: [u8; 32],
    pub inputs_digest: [u8; 32],
    pub findings_digest: [u8; 32],
    /// Bound to the disclosed SoD policy bytes, not proof of its activation.
    pub policy_oid: [u8; 32],
    pub decision_card: Vec<u8>,
    pub decision_card_digest: [u8; 32],
}

/// Authenticated entry facts, selected at the certificate's exact frontier.
pub(super) struct Entry {
    pub identity: u128,
    pub digest: [u8; 32],
    pub recorded_at: u64,
    pub class: u16,
    pub legs: Vec<(u32, i128)>,
    pub supersession: Vec<(u128, [u8; 32], u8)>,
}

pub(super) struct Registry {
    pub unit_scales: BTreeMap<u32, u8>,
    pub policy_oid: [u8; 32],
}

fn framed_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    hash_parts(domain, &[&(bytes.len() as u32).to_le_bytes(), bytes])
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + FORMAT.len()) == Some(FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "procedure certificate exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "procedure.format")? != FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported procedure certificate format",
        ));
    }
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "procedure.source")?;
    // Retained for native replay only: this witness never establishes approval
    // authority or contributes facts to the independent round-amount fold.
    r.bytes(1024 * 1024, "procedure.approval_witness")?;
    let registry_digest = r.fixed("procedure.registry")?;
    r.u128("procedure.producer")?;
    r.fixed::<32>("procedure.capability_commitment")?;
    let output = r.bytes(MAX_OUTPUT, "procedure.output")?;
    let digest = r.fixed("procedure.digest")?;
    r.finish("procedure certificate")?;
    if framed_hash(DIGEST_DOMAIN, &bytes[..bytes.len() - 32]) != digest {
        return Err(failed(
            "certificate_digest",
            "procedure certificate commitment differs",
        ));
    }
    let mut question = Reader::new(output);
    if question.bytes(64, "procedure.output_format")? != OUTPUT_FORMAT
        || text(&mut question, 128, "procedure.id")? != ID
        || question.u16("procedure.version")? != 1
        || question.u8("procedure.claim")? != 0
        || text(&mut question, 128, "procedure.evidence")? != "FA-EVID-L01"
    {
        return Err(failed(
            "procedure_profile",
            "only statistical jet.round_amounts v1 is supported",
        ));
    }
    let book = question.fixed("procedure.book")?;
    let known_at = question.u64("procedure.known_at")?;
    if question.present("procedure.effective_through")? {
        return Err(failed(
            "procedure_profile",
            "round-amount verification requires no effective-date cutoff",
        ));
    }
    if question.count(1, 20, "procedure.parameters")? != 1
        || text(&mut question, 64, "procedure.parameter")? != "round_power"
    {
        return Err(failed(
            "procedure_profile",
            "round_power must be the only procedure parameter",
        ));
    }
    let round_power = u32::try_from(question.i128("procedure.round_power")?)
        .ok()
        .filter(|power| *power <= 30)
        .ok_or_else(|| failed("procedure_profile", "round_power must be in 0..=30"))?;
    if question.count(0, 8, "procedure.inputs")? != 0 {
        return Err(failed(
            "procedure_profile",
            "round-amount input handles are unsupported",
        ));
    }
    // All remaining output fields are reconstructed below and compared byte
    // for byte. In particular no claimed count controls an allocation here.
    Ok(Certificate {
        source,
        registry_digest,
        output,
        digest,
        book,
        known_at,
        round_power,
    })
}

fn parameters(w: &mut Writer, power: u32) {
    w.count(1).bytes(b"round_power").i128(i128::from(power));
}

fn coordinate(w: &mut Writer, book: &[u8; 16], known_at: u64) {
    w.fixed(book).u64(known_at).u8(0);
}

fn finding(w: &mut Writer, value: &VerifiedRoundAmountFinding, live_legs: u64) {
    w.bytes(ID.as_bytes())
        .u16(1)
        .u8(value.severity)
        .bytes(b"round_legs")
        .i128(value.round_legs.len() as i128)
        .u8(0)
        .u64(live_legs)
        .count(value.round_legs.len() + 1)
        .u8(1)
        .u128(value.entry);
    for ordinal in &value.round_legs {
        w.u8(2).u128(value.entry).u16(*ordinal);
    }
    w.bytes(value.narrative.as_bytes());
}

fn candidate(w: &mut Writer, action: &[u8], parameter: i128, score: i128) {
    w.bytes(action).i128(parameter).i128(score);
}

/// Independent FADC v1 threshold law. The policy epoch is a disclosed
/// identifier; nothing here claims that its approval rules admitted entries.
fn decision_card(policy_oid: &[u8; 32], power: u32, population: u64) -> Vec<u8> {
    let mut state = Writer::default();
    state.bytes(ID.as_bytes()).u16(1).u64(population);
    parameters(&mut state, power);
    let calibrated = population >= 100;
    let power = i128::from(power);
    let mut w = Writer::default();
    w.fixed(b"FADC")
        .u16(1)
        .u8(1)
        .fixed(policy_oid)
        .u8(2)
        .bytes(&state.buf)
        .count(2);
    candidate(&mut w, b"registry_default", 0, 100);
    candidate(
        &mut w,
        b"split_conformal_calibrated",
        power,
        if calibrated { 250 } else { 0 },
    );
    w.count(2)
        .bytes(b"param.round_power")
        .i128(power)
        .u8(0)
        .bytes(b"population")
        .i128(i128::from(population))
        .u8(0);
    if calibrated {
        candidate(&mut w, b"split_conformal_calibrated", power, 250);
        w.fixed(&150i64.to_le_bytes()).fixed(&650i64.to_le_bytes());
    } else {
        candidate(&mut w, b"registry_default", 0, 0);
        w.fixed(&(-200i64).to_le_bytes())
            .fixed(&2200i64.to_le_bytes());
    }
    candidate(&mut w, b"registry_default", 0, 0);
    if calibrated {
        w.u8(6).bytes(b"split_conformal_calibrated");
    } else {
        w.u8(3).u64(2400).u64(1500);
    }
    w.buf
}

/// Memoized parity traversal: a long reversal chain is linear work, not a
/// quadratic walk for every entry, and cycles are rejected without recursion.
fn liveness(entries: &[Entry]) -> Result<BTreeMap<u128, bool>, ReportError> {
    let mut identities = BTreeMap::new();
    let mut reversed_by = BTreeMap::new();
    for entry in entries {
        if identities.insert(entry.identity, entry).is_some() {
            return Err(failed("procedure_lineage", "duplicate entry identity"));
        }
    }
    for entry in entries
        .iter()
        .filter(|e| !e.legs.is_empty() && e.class != 2)
    {
        if entry.class == 4 {
            let [(target, digest, 1)] = entry.supersession.as_slice() else {
                return Err(failed(
                    "procedure_lineage",
                    "reversal requires exactly one Reverses target",
                ));
            };
            let original = identities
                .get(target)
                .ok_or_else(|| failed("procedure_lineage", "reversal target is absent"))?;
            if original.digest != *digest
                || original.recorded_at > entry.recorded_at
                || original.class == 2
                || original.legs.is_empty()
                || reversed_by.insert(*target, entry.identity).is_some()
            {
                return Err(failed(
                    "procedure_lineage",
                    "invalid or duplicate reversal target",
                ));
            }
        }
    }
    let mut live = BTreeMap::new();
    for entry in entries
        .iter()
        .filter(|e| !e.legs.is_empty() && e.class != 2)
    {
        if live.contains_key(&entry.identity) {
            continue;
        }
        let mut path = Vec::new();
        let mut visiting = BTreeSet::new();
        let mut current = entry.identity;
        let mut parity = loop {
            if let Some(value) = live.get(&current) {
                break *value;
            }
            if !visiting.insert(current) {
                return Err(failed("procedure_lineage", "reversal lineage cycles"));
            }
            path.push(current);
            match reversed_by.get(&current) {
                Some(next) => current = *next,
                None => break true,
            }
        };
        // A previously memoized endpoint was not appended to path; an
        // unvisited terminal was. Toggle once before the former's predecessor.
        if live.contains_key(&current) {
            parity = !parity;
        }
        for identity in path.into_iter().rev() {
            live.insert(identity, parity);
            parity = !parity;
        }
    }
    Ok(live)
}

pub(super) fn replay(
    request: &Certificate<'_>,
    book: [u8; 16],
    known_at: u64,
    entries: Vec<Entry>,
    registry: &Registry,
) -> Result<(VerifiedProcedure, Vec<u8>), ReportError> {
    if request.book != book || request.known_at != known_at {
        return Err(failed(
            "procedure_selection",
            "procedure and native source coordinates differ",
        ));
    }
    let (verified, output) = recompute(book, known_at, request.round_power, entries, registry)?;
    if output != request.output {
        return Err(failed(
            "procedure_recomputation",
            "procedure population, work, findings, citations, digests or decision card differ from independent replay",
        ));
    }
    Ok((verified, output))
}

fn recompute(
    book: [u8; 16],
    known_at: u64,
    round_power: u32,
    mut entries: Vec<Entry>,
    registry: &Registry,
) -> Result<(VerifiedProcedure, Vec<u8>), ReportError> {
    // The immutable payload admits both a historical key identity and the
    // newer target-derived Replacement identity. Neither may be guessed when
    // reproducing a full population digest or the exact leg citations.
    if entries
        .iter()
        .any(|entry| entry.class == 5 || entry.supersession.iter().any(|(_, _, kind)| *kind == 2))
    {
        return Err(failed(
            "procedure_profile",
            "replacement identities require a future procedure proof profile",
        ));
    }
    entries.sort_unstable_by_key(|entry| entry.identity);
    let live = liveness(&entries)?;
    let population = entries.len() as u64;
    let mut inputs = Writer::default();
    inputs.u64(known_at).u8(0).count(entries.len());
    for entry in &entries {
        inputs
            .u128(entry.identity)
            .fixed(&entry.digest)
            .u64(entry.recorded_at);
    }
    let inputs_digest = hash_parts(b"fa:lantern-inputs:v1", &[&inputs.buf]);
    let mut params = Writer::default();
    params.bytes(ID.as_bytes()).u16(1);
    parameters(&mut params, round_power);
    params.count(0);
    let parameters_digest = hash_parts(b"fa:lantern-parameters:v1", &[&params.buf]);
    let factor = 10i128
        .checked_pow(round_power)
        .ok_or_else(|| failed("procedure_arithmetic", "round factor overflow"))?;
    let mut live_entries = 0u64;
    let mut live_legs = 0u64;
    let mut findings = Vec::new();
    for entry in &entries {
        if entry.legs.is_empty()
            || matches!(entry.class, 2 | 4)
            || !live.get(&entry.identity).copied().unwrap_or(false)
        {
            continue;
        }
        live_entries += 1;
        let mut round_legs = Vec::new();
        for (ordinal, (unit, mantissa)) in entry.legs.iter().enumerate() {
            live_legs += 1;
            let scale = registry
                .unit_scales
                .get(unit)
                .ok_or_else(|| failed("procedure_units", "posting uses an unregistered unit"))?;
            let base = 10i128
                .checked_pow(u32::from(*scale))
                .and_then(|one| one.checked_mul(factor))
                .ok_or_else(|| {
                    failed(
                        "procedure_arithmetic",
                        "round base exceeds exact i128 arithmetic",
                    )
                })?;
            if *mantissa != 0 && mantissa.checked_rem(base) == Some(0) {
                round_legs.push(
                    u16::try_from(ordinal).map_err(|_| {
                        failed("bounded_input", "procedure leg ordinal exceeds u16")
                    })?,
                );
            }
        }
        if !round_legs.is_empty() {
            if round_legs.len() >= MAX_CITES {
                return Err(failed(
                    "bounded_input",
                    "procedure entry and leg citations exceed 4096",
                ));
            }
            if findings.len() >= MAX_FINDINGS {
                return Err(failed(
                    "bounded_input",
                    "procedure findings exceed the certificate bound",
                ));
            }
            let narrative = format!(
                "{} of {} legs are whole multiples of 10^{} units",
                round_legs.len(),
                entry.legs.len(),
                round_power
            );
            findings.push(VerifiedRoundAmountFinding {
                entry: entry.identity,
                severity: if round_legs.len() == entry.legs.len() {
                    2
                } else {
                    1
                },
                round_legs,
                narrative,
            });
        }
    }
    // The first citation is always the unique entry identity. Canonical
    // little-endian citation bytes, rather than numeric VId order, break ties.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.round_legs.len().cmp(&a.round_legs.len()))
            .then_with(|| a.entry.to_le_bytes().cmp(&b.entry.to_le_bytes()))
            .then_with(|| a.narrative.cmp(&b.narrative))
    });
    let mut encoded_findings = Writer::default();
    encoded_findings.count(findings.len());
    for value in &findings {
        finding(&mut encoded_findings, value, live_legs);
        if encoded_findings.buf.len() > MAX_OUTPUT {
            return Err(failed("bounded_input", "procedure findings exceed 32 MiB"));
        }
    }
    let mut finding_inputs = Writer::default();
    finding_inputs
        .bytes(ID.as_bytes())
        .u16(1)
        .fixed(&parameters_digest)
        .fixed(&inputs_digest);
    coordinate(&mut finding_inputs, &book, known_at);
    let findings_digest = hash_parts(
        b"fa:lantern-findings:v1",
        &[&finding_inputs.buf, &encoded_findings.buf],
    );
    let decision_card = decision_card(&registry.policy_oid, round_power, population);
    let decision_card_digest = framed_hash(b"fa:decision-card:v1", &decision_card);
    let mut output = Writer::default();
    output
        .bytes(OUTPUT_FORMAT)
        .bytes(ID.as_bytes())
        .u16(1)
        .u8(0)
        .bytes(b"FA-EVID-L01");
    coordinate(&mut output, &book, known_at);
    parameters(&mut output, round_power);
    output
        .count(0)
        .fixed(&parameters_digest)
        .fixed(&inputs_digest)
        .u64(population)
        .u64(live_entries)
        .u64(live_legs)
        .u64(0)
        .fixed(&encoded_findings.buf)
        .fixed(&findings_digest)
        .bytes(&decision_card)
        .fixed(&decision_card_digest);
    Ok((
        VerifiedProcedure {
            procedure: ID.into(),
            version: 1,
            book_id: book,
            known_at,
            round_power,
            population,
            live_entries,
            live_legs,
            findings,
            parameters_digest,
            inputs_digest,
            findings_digest,
            policy_oid: registry.policy_oid,
            decision_card,
            decision_card_digest,
        },
        output.buf,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        Registry {
            unit_scales: BTreeMap::from([(1, 2), (2, 0)]),
            policy_oid: [7; 32],
        }
    }

    fn entry(identity: u128, class: u16, legs: Vec<(u32, i128)>) -> Entry {
        Entry {
            identity,
            digest: hash_parts(b"test-entry", &[&identity.to_le_bytes()]),
            recorded_at: 1,
            class,
            legs,
            supersession: Vec::new(),
        }
    }

    fn population() -> Vec<Entry> {
        vec![
            entry(
                1,
                1,
                vec![(1, 9_007_199_254_800_000), (1, -9_007_199_254_800_000)],
            ),
            entry(256, 1, vec![(2, 1000), (2, 1000)]),
            entry(2, 1, vec![(1, 100_000), (1, 50_001), (1, 49_999)]),
            entry(3, 2, vec![(1, 100_000), (1, 100_000)]),
            entry(4, 1, vec![(1, 0), (1, 0)]),
            entry(5, 17, Vec::new()),
        ]
    }

    #[test]
    fn exact_scale_zero_and_large_amounts_use_live_legs_and_canonical_cite_order() {
        let (verified, output) = recompute([1; 16], 9, 3, population(), &registry()).unwrap();
        assert_eq!(
            (
                verified.population,
                verified.live_entries,
                verified.live_legs
            ),
            (6, 4, 9)
        );
        assert_eq!(
            verified
                .findings
                .iter()
                .map(|f| (f.entry, f.severity, f.round_legs.clone()))
                .collect::<Vec<_>>(),
            vec![(256, 2, vec![0, 1]), (1, 2, vec![0, 1]), (2, 1, vec![0])]
        );
        assert_eq!(
            verified.findings[2].narrative,
            "1 of 3 legs are whole multiples of 10^3 units"
        );
        let mut reordered = population();
        reordered.reverse();
        assert_eq!(
            recompute([1; 16], 9, 3, reordered, &registry()).unwrap().1,
            output
        );
        let request = Certificate {
            source: &[],
            registry_digest: [0; 32],
            output: &output,
            digest: [0; 32],
            book: [1; 16],
            known_at: 9,
            round_power: 3,
        };
        assert_eq!(
            replay(&request, [1; 16], 9, population(), &registry())
                .unwrap()
                .0,
            verified
        );
        let mut forged = output.clone();
        *forged.last_mut().unwrap() ^= 1;
        let forged = Certificate {
            output: &forged,
            ..request
        };
        assert_eq!(
            replay(&forged, [1; 16], 9, population(), &registry())
                .unwrap_err()
                .predicate,
            "procedure_recomputation"
        );
        assert_eq!(
            replay(&request, [2; 16], 9, population(), &registry())
                .unwrap_err()
                .predicate,
            "procedure_selection"
        );
    }

    #[test]
    fn reversal_chains_restore_by_parity_even_when_identity_order_is_reversed() {
        for length in 0..64 {
            let mut entries = vec![entry(1000, 1, vec![(1, 100_000), (1, 100_000)])];
            for ordinal in 1..=length {
                let previous = entries.last().unwrap();
                let mut reversal = entry(1000 - ordinal, 4, previous.legs.clone());
                reversal
                    .supersession
                    .push((previous.identity, previous.digest, 1));
                entries.push(reversal);
            }
            let (verified, _) = recompute([1; 16], 9, 3, entries, &registry()).unwrap();
            assert_eq!(verified.population, length as u64 + 1);
            assert_eq!(verified.live_entries, u64::from(length % 2 == 0));
            assert_eq!(verified.live_legs, 2 * u64::from(length % 2 == 0));
            assert_eq!(verified.findings.len(), usize::from(length % 2 == 0));
            if let Some(finding) = verified.findings.first() {
                assert_eq!(finding.entry, 1000);
            }
        }
    }

    #[test]
    fn invalid_lineage_unknown_units_and_overflow_cannot_produce_a_result() {
        let original = entry(1, 1, vec![(1, 100_000)]);
        let mut first = entry(2, 4, original.legs.clone());
        first
            .supersession
            .push((original.identity, original.digest, 1));
        let mut second = entry(3, 4, original.legs.clone());
        second.supersession = first.supersession.clone();
        assert_eq!(
            liveness(&[original, first, second]).unwrap_err().predicate,
            "procedure_lineage"
        );

        let mut a = entry(1, 4, vec![(1, 100_000)]);
        let mut b = entry(2, 4, a.legs.clone());
        a.supersession.push((b.identity, b.digest, 1));
        b.supersession.push((a.identity, a.digest, 1));
        assert_eq!(
            liveness(&[a, b]).unwrap_err().predicate,
            "procedure_lineage"
        );

        let mut replacement = entry(1, 1, vec![(1, 100_000)]);
        replacement.supersession.push((2, [0; 32], 2));
        assert_eq!(
            recompute([1; 16], 9, 3, vec![replacement], &registry())
                .unwrap_err()
                .predicate,
            "procedure_profile"
        );
        let unknown = entry(1, 1, vec![(99, 100_000)]);
        assert_eq!(
            recompute([1; 16], 9, 3, vec![unknown], &registry())
                .unwrap_err()
                .predicate,
            "procedure_units"
        );
        let mut large_scale = registry();
        large_scale.unit_scales.insert(1, 38);
        assert_eq!(
            recompute([1; 16], 9, 3, population(), &large_scale)
                .unwrap_err()
                .predicate,
            "procedure_arithmetic"
        );
        let too_many_cites = entry(1, 1, vec![(1, 100_000); MAX_CITES]);
        assert_eq!(
            recompute([1; 16], 9, 3, vec![too_many_cites], &registry())
                .unwrap_err()
                .predicate,
            "bounded_input"
        );
    }

    #[test]
    fn decision_card_changes_at_the_total_entry_population_threshold() {
        // Controls affect the decision population without creating monetary
        // work or findings. This distinguishes it from the live-leg population.
        let controls = |n| (0..n).map(|id| entry(id, 17, Vec::new())).collect();
        let (small, _) = recompute([1; 16], 9, 2, controls(99), &registry()).unwrap();
        let (large, _) = recompute([1; 16], 9, 2, controls(100), &registry()).unwrap();
        assert_eq!(
            (small.live_entries, large.live_legs, large.findings.len()),
            (0, 0, 0)
        );
        assert_eq!(small.decision_card[small.decision_card.len() - 17], 3);
        assert_eq!(
            &small.decision_card[small.decision_card.len() - 16..small.decision_card.len() - 8],
            &2400u64.to_le_bytes()
        );
        assert_eq!(
            &small.decision_card[small.decision_card.len() - 8..],
            &1500u64.to_le_bytes()
        );
        let action = b"split_conformal_calibrated";
        let suffix = large.decision_card.len() - action.len() - 5;
        assert_eq!(large.decision_card[suffix], 6);
        assert_eq!(&large.decision_card[suffix + 5..], action);
        assert_ne!(small.decision_card_digest, large.decision_card_digest);
    }
}
