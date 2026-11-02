//! Two independently replayed original v2 equity statements at fixed frontiers.
//! The common question is a recipient input. A signed bundle does not choose
//! the recipient's dates, unit scope or owner-account classification for them.

use super::equity::{self, EquityRollForwardUnit, VerifiedEquityRollForward};
use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, Selection, failed, hash_parts, text};
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg};

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:equity-roll-forward-diff-certificate:v1";
pub(super) const DIGEST_DOMAIN: &[u8] = b"fa:equity-roll-forward-diff-certificate-digest:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:equity-roll-forward-diff:v1";
const REQUEST_FORMAT: &[u8] = b"fa:equity-roll-forward-diff-request:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:equity-roll-forward-diff-source:v1";
const MAX_SCOPE: usize = 4096;
const MAX_REQUEST_BYTES: usize = 4 + 64 + 16 + 4 + 256 + 8 + 12 + MAX_SCOPE * 36;
const LINE_CODES: [&str; 15] = [
    "opening_contributed_equity",
    "opening_unclosed_earnings",
    "opening_total_equity",
    "prior_period_adjustments",
    "opening_equity_as_adjusted",
    "net_income",
    "issuances",
    "distributions",
    "other_equity_movements",
    "closing_transfers_net",
    "net_equity_change",
    "closing_contributed_equity",
    "closing_unclosed_earnings",
    "closing_total_equity",
    "equity_tie_out_residual",
];

/// Independently retained accounting question, never inferred from the bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardDiffRequest {
    pub before: u64,
    pub after: u64,
    pub label: String,
    pub effective_from: i32,
    pub effective_through: i32,
    pub units: Vec<u32>,
    pub issuance_accounts: Vec<u128>,
    pub distribution_accounts: Vec<u128>,
}

impl EquityRollForwardDiffRequest {
    fn validate(&self) -> Result<(), ReportError> {
        let ordered =
            |ids: &[u128]| ids.len() <= MAX_SCOPE && ids.windows(2).all(|pair| pair[0] < pair[1]);
        if self.before > self.after
            || self.label.trim().is_empty()
            || self.label.len() > 256
            || self.effective_from > self.effective_through
            || self.units.is_empty()
            || self.units.len() > MAX_SCOPE
            || !self.units.windows(2).all(|pair| pair[0] < pair[1])
            || !ordered(&self.issuance_accounts)
            || !ordered(&self.distribution_accounts)
            || self
                .issuance_accounts
                .iter()
                .any(|id| self.distribution_accounts.binary_search(id).is_ok())
        {
            return Err(failed(
                "equity_diff_request",
                "expected equity question needs ordered fixed frontiers and dates, a nonempty label, 1..=4096 ascending units, and bounded ascending disjoint owner roles",
            ));
        }
        Ok(())
    }

    /// Decode the strictly bounded portable recipient expectation, using this
    /// verifier's independent framing rather than the producer's decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReportError> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(failed(
                "bounded_input",
                "equity request exceeds its scope bound",
            ));
        }
        let mut r = Reader::new(bytes);
        if r.bytes(64, "equity_diff_request.format")? != REQUEST_FORMAT {
            return Err(failed("equity_diff_request", "unsupported request format"));
        }
        let before = r.u64("equity_diff_request.before")?;
        let after = r.u64("equity_diff_request.after")?;
        let label = text(&mut r, 256, "equity_diff_request.label")?.to_owned();
        let effective_from = r.i32("equity_diff_request.from")?;
        let effective_through = r.i32("equity_diff_request.through")?;
        let count = r.count(MAX_SCOPE, 4, "equity_diff_request.units")?;
        let mut units = Vec::with_capacity(count);
        for _ in 0..count {
            units.push(r.u32("equity_diff_request.unit")?);
        }
        let roles = |r: &mut Reader<'_>| -> Result<Vec<u128>, ReportError> {
            let count = r.count(MAX_SCOPE, 16, "equity_diff_request.roles")?;
            let mut result = Vec::with_capacity(count);
            for _ in 0..count {
                result.push(r.u128("equity_diff_request.account")?);
            }
            Ok(result)
        };
        let issuance_accounts = roles(&mut r)?;
        let distribution_accounts = roles(&mut r)?;
        r.finish("equity comparison request")?;
        let result = Self {
            before,
            after,
            label,
            effective_from,
            effective_through,
            units,
            issuance_accounts,
            distribution_accounts,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReportError> {
        self.validate()?;
        let mut w = Writer::default();
        w.bytes(REQUEST_FORMAT)
            .u64(self.before)
            .u64(self.after)
            .bytes(self.label.as_bytes())
            .i32(self.effective_from)
            .i32(self.effective_through)
            .count(self.units.len());
        for unit in &self.units {
            w.u32(*unit);
        }
        for roles in [&self.issuance_accounts, &self.distribution_accounts] {
            w.count(roles.len());
            for id in roles {
                w.u128(*id);
            }
        }
        Ok(w.buf)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardDiffLine {
    pub code: &'static str,
    pub before: i128,
    pub after: i128,
    pub delta: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardDiffUnit {
    pub unit_id: u32,
    pub lines: Vec<EquityRollForwardDiffLine>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEquityRollForwardDiff {
    pub before: VerifiedEquityRollForward,
    pub after: VerifiedEquityRollForward,
    /// Commitments to complete original v2 report bytes, including all movement
    /// and case citations, under the comparison source domain.
    pub before_digest: [u8; 32],
    pub after_digest: [u8; 32],
    pub units: Vec<EquityRollForwardDiffUnit>,
}

pub(super) struct Certificate<'a> {
    pub before: &'a [u8],
    pub after: &'a [u8],
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "equity comparison exceeds 64 MiB"));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "equity_diff.format")? != CERTIFICATE_FORMAT {
        return Err(failed("supported_report", "unsupported equity comparison"));
    }
    let before = r.bytes(MAX_REPORT_BUNDLE_BYTES, "equity_diff.before")?;
    let after = r.bytes(MAX_REPORT_BUNDLE_BYTES, "equity_diff.after")?;
    // Producer identity and capability are authenticated transport parameters;
    // they do not independently prove original admission or economic judgment.
    r.u128("equity_diff.producer")?;
    r.fixed::<32>("equity_diff.capability")?;
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "equity_diff.output")?;
    let digest = r.fixed("equity_diff.digest")?;
    r.finish("equity comparison certificate")?;
    let body = &bytes[..bytes.len() - 32];
    if commitment(DIGEST_DOMAIN, body) != digest {
        return Err(failed(
            "certificate_digest",
            "equity comparison commitment differs",
        ));
    }
    Ok(Certificate {
        before,
        after,
        output,
        digest,
    })
}

fn commitment(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    hash_parts(domain, &[&(bytes.len() as u32).to_le_bytes(), bytes])
}

struct Source<'a> {
    equity: equity::Certificate<'a>,
    lead: super::roll_forward::Certificate<'a>,
    native: super::Certificate<'a>,
}

fn source(bytes: &[u8]) -> Result<Source<'_>, ReportError> {
    let equity = equity::decode(bytes)?;
    if equity.version != 2 {
        return Err(failed(
            "equity_diff_source",
            "equity comparisons require original v2 sources",
        ));
    }
    let lead = super::roll_forward::decode(equity.source)?;
    let native = super::certificate(lead.source)?;
    if native.branch != [0; 16]
        || native.time_selection.is_some()
        || native.dimension.is_some()
        || native.functional
        || native.selection != Selection::AsOf(lead.effective_through)
    {
        return Err(failed(
            "equity_diff_source",
            "equity comparisons require native sequence-selected trunk sources at their closing day",
        ));
    }
    Ok(Source {
        equity,
        lead,
        native,
    })
}

pub(super) fn bind(
    certificate: &Certificate<'_>,
    expected: &EquityRollForwardDiffRequest,
) -> Result<(), ReportError> {
    expected.validate()?;
    let before = source(certificate.before)?;
    let after = source(certificate.after)?;
    for (value, known_at) in [(&before, expected.before), (&after, expected.after)] {
        if value.native.known_at != known_at
            || value.lead.label != expected.label
            || value.lead.effective_from != expected.effective_from
            || value.lead.effective_through != expected.effective_through
            || value.lead.units != expected.units
            || value.equity.issuance_accounts != expected.issuance_accounts
            || value.equity.distribution_accounts != expected.distribution_accounts
        {
            return Err(failed(
                "equity_diff_request",
                "source differs from the recipient's fixed equity frontiers, label, dates, units or owner roles",
            ));
        }
    }
    if before.native.book != after.native.book
        || before.native.registry_digest != after.native.registry_digest
        || expected.before == expected.after && certificate.before != certificate.after
    {
        return Err(failed(
            "equity_diff_source",
            "sources differ in book, shared registry closure or bytes at the same frontier",
        ));
    }
    Ok(())
}

fn amounts(unit: &EquityRollForwardUnit) -> [i128; 15] {
    [
        unit.opening_contributed_equity,
        unit.opening_unclosed_earnings,
        unit.opening_total_equity,
        unit.prior_period_adjustments,
        unit.opening_equity_as_adjusted,
        unit.net_income,
        unit.issuances,
        unit.distributions,
        unit.other_equity_movements,
        unit.closing_transfers_net,
        unit.net_equity_change,
        unit.closing_contributed_equity,
        unit.closing_unclosed_earnings,
        unit.closing_total_equity,
        unit.equity_tie_out_residual,
    ]
}

pub(super) fn derive(
    certificate: &Certificate<'_>,
    before: VerifiedEquityRollForward,
    after: VerifiedEquityRollForward,
) -> Result<(VerifiedEquityRollForwardDiff, Vec<u8>), ReportError> {
    if before.units.len() != after.units.len() || before.units.is_empty() {
        return Err(failed("equity_diff_source", "source unit scopes differ"));
    }
    let before_digest = commitment(SOURCE_DOMAIN, source(certificate.before)?.equity.output);
    let after_digest = commitment(SOURCE_DOMAIN, source(certificate.after)?.equity.output);
    let mut units = Vec::with_capacity(before.units.len());
    let mut w = Writer::default();
    w.bytes(OUTPUT_FORMAT)
        .fixed(&before.book_id)
        .fixed(&[0; 16])
        .u64(before.known_at)
        .u64(after.known_at)
        .fixed(&before_digest)
        .fixed(&after_digest)
        .bytes(before.label.as_bytes())
        .i32(before.effective_from)
        .i32(before.effective_through)
        .count(before.units.len());
    for (old, new) in before.units.iter().zip(&after.units) {
        if old.unit_id != new.unit_id {
            return Err(failed(
                "equity_diff_source",
                "source unit identities differ",
            ));
        }
        w.u32(old.unit_id);
        let mut lines = Vec::with_capacity(15);
        for ((code, before), after) in LINE_CODES.into_iter().zip(amounts(old)).zip(amounts(new)) {
            let delta = after.checked_sub(before).ok_or_else(|| {
                failed(
                    "exact_arithmetic",
                    format!("equity comparison overflow in {code}"),
                )
            })?;
            w.i128(before).i128(after).i128(delta);
            lines.push(EquityRollForwardDiffLine {
                code,
                before,
                after,
                delta,
            });
        }
        units.push(EquityRollForwardDiffUnit {
            unit_id: old.unit_id,
            lines,
        });
    }
    if w.buf != certificate.output {
        return Err(failed(
            "equity_diff_recomputation",
            "complete source commitments or exact equity before/after/delta rows differ from the original reports",
        ));
    }
    Ok((
        VerifiedEquityRollForwardDiff {
            before,
            after,
            before_digest,
            after_digest,
            units,
        },
        w.buf,
    ))
}

/// Reconstruct the earlier prefix independently. The caller has already replayed
/// the later complete source against this same authenticated journal closure.
#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    certificate: &Certificate<'_>,
    after: VerifiedEquityRollForward,
    registered_units: &[u32],
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    bodies: &[(u64, &[u8])],
    legs: &[Vec<Leg>],
) -> Result<(VerifiedEquityRollForwardDiff, Vec<u8>), ReportError> {
    let before = source(certificate.before)?;
    let bodies = crate::migration_balance::report_bodies_at(
        envelopes,
        records,
        bodies,
        before.native.known_at,
    )
    .map_err(|e| failed("migration_visibility", e.to_string()))?;
    let historical = super::historical_inputs(&before.native, envelopes, records, &bodies)?;
    let native = super::replay_trial_balance(
        &before.native,
        &historical.schema,
        None,
        &historical.dimension_history,
        envelopes,
        records,
        legs,
        &historical.infos,
        &historical.resolved,
        &historical.visible_migrations,
    )?;
    let (lead, _) = super::roll_forward::replay(
        &before.lead,
        before.native.book,
        before.native.known_at,
        before.native.digest,
        registered_units,
        &historical.schema,
        envelopes,
        &historical.infos,
        legs,
        &historical.visible_migrations,
        &native.rows,
    )?;
    let (report, _) = equity::replay(
        &before.equity,
        lead,
        before.lead.digest,
        &historical.schema,
        envelopes,
        &historical.infos,
    )?;
    derive(certificate, report, after)
}
