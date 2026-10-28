//! Independent Statement of Changes in Equity over an authenticated lead schedule.
//! Every historical equity, revenue and expense leaf must be present, including
//! zero accounts. Owner roles are authenticated report parameters, not inferred
//! economic facts. Closing transfers must conserve total equity exactly.

use super::metadata::{EntryInfo, Schema};
use super::roll_forward::{RollForwardAccount, VerifiedRollForward};
use super::statement::Sum;
use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, failed, hash_parts, text};
use crate::codec::{Reader, Writer};
use crate::envelope::LeafEnvelope;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const CERTIFICATE_FORMAT_V1: &[u8] = b"fa:equity-roll-forward-certificate:v1";
pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:equity-roll-forward-certificate:v2";
pub(super) const DIGEST_DOMAIN_V1: &[u8] = b"fa:equity-roll-forward-certificate-digest:v1";
pub(super) const DIGEST_DOMAIN: &[u8] = b"fa:equity-roll-forward-certificate-digest:v2";
const REPORT_FORMAT_V1: &[u8] = b"fa:equity-roll-forward-report:v1";
const REPORT_FORMAT: &[u8] = b"fa:equity-roll-forward-report:v2";
const STATEMENT_FORMAT_V1: &[u8] = b"fa:equity-roll-forward:v1";
const STATEMENT_FORMAT: &[u8] = b"fa:equity-roll-forward:v2";
const MAX_SCOPE: usize = 4096;
type AdjustmentCitations = (Option<u32>, Option<(String, String)>);

pub(super) struct Certificate<'a> {
    pub version: u16,
    pub source: &'a [u8],
    pub issuance_accounts: Vec<u128>,
    pub distribution_accounts: Vec<u128>,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EquityActivityKind {
    Issuance,
    Distribution,
    ClosingTransfer,
    OtherEquity,
    PriorPeriodAdjustment,
}

impl EquityActivityKind {
    fn tag(self) -> u8 {
        match self {
            Self::Issuance => 1,
            Self::Distribution => 2,
            Self::ClosingTransfer => 3,
            Self::OtherEquity => 4,
            Self::PriorPeriodAdjustment => 5,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Issuance => "issuance",
            Self::Distribution => "distribution",
            Self::ClosingTransfer => "closing_transfer",
            Self::OtherEquity => "other_equity",
            Self::PriorPeriodAdjustment => "prior_period_adjustment",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityMovement {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub recorded_seq: u64,
    pub effective_day: i32,
    pub class: u16,
    pub kind: EquityActivityKind,
    pub account_id: u128,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
    pub case_ordinal: Option<u32>,
    pub relates_to: Option<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardUnit {
    pub unit_id: u32,
    pub opening_contributed_equity: i128,
    pub opening_unclosed_earnings: i128,
    pub opening_total_equity: i128,
    pub prior_period_adjustments: i128,
    pub opening_equity_as_adjusted: i128,
    pub net_income: i128,
    pub issuances: i128,
    pub distributions: i128,
    pub other_equity_movements: i128,
    pub closing_transfers_net: i128,
    pub net_equity_change: i128,
    pub closing_contributed_equity: i128,
    pub closing_unclosed_earnings: i128,
    pub closing_total_equity: i128,
    pub equity_tie_out_residual: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEquityRollForward {
    /// V1 preserves the originally certified classification; V2 reports
    /// prior-period adjustments separately with their authenticated lineage.
    pub format_version: u16,
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub label: String,
    pub effective_from: i32,
    pub effective_through: i32,
    pub source_certificate_digest: [u8; 32],
    pub issuance_accounts: Vec<u128>,
    pub distribution_accounts: Vec<u128>,
    pub accounts: Vec<RollForwardAccount>,
    pub units: Vec<EquityRollForwardUnit>,
    pub movements: Vec<EquityMovement>,
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && matches!(
            bytes.get(4..4 + CERTIFICATE_FORMAT.len()),
            Some(format) if format == CERTIFICATE_FORMAT || format == CERTIFICATE_FORMAT_V1
        )
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "equity certificate exceeds 64 MiB"));
    }
    let mut r = Reader::new(bytes);
    let version = match r.bytes(64, "equity.format")? {
        CERTIFICATE_FORMAT_V1 => 1,
        CERTIFICATE_FORMAT => 2,
        _ => {
            return Err(failed(
                "supported_report",
                "unsupported equity certificate format",
            ));
        }
    };
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "equity.source")?;
    if !super::roll_forward::recognizes(source) {
        return Err(failed(
            "supported_report",
            "equity requires one native roll-forward source",
        ));
    }
    let roles = |r: &mut Reader<'_>| -> Result<Vec<u128>, ReportError> {
        let count = r.count(MAX_SCOPE, 16, "equity.role_accounts")?;
        let mut accounts = Vec::with_capacity(count);
        for _ in 0..count {
            accounts.push(r.u128("equity.role_account")?);
        }
        if !accounts.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(failed(
                "equity_selection",
                "equity role accounts must be strictly ordered",
            ));
        }
        Ok(accounts)
    };
    let issuance_accounts = roles(&mut r)?;
    let distribution_accounts = roles(&mut r)?;
    if issuance_accounts
        .iter()
        .any(|id| distribution_accounts.binary_search(id).is_ok())
    {
        return Err(failed(
            "equity_selection",
            "an equity account cannot have both owner roles",
        ));
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "equity.output")?;
    let digest = r.fixed("equity.digest")?;
    r.finish("equity certificate")?;
    let body = &bytes[..bytes.len() - 32];
    let domain = if version == 1 {
        DIGEST_DOMAIN_V1
    } else {
        DIGEST_DOMAIN
    };
    if hash_parts(domain, &[&(body.len() as u32).to_le_bytes(), body]) != digest {
        return Err(failed(
            "certificate_digest",
            "equity certificate differs from its commitment",
        ));
    }
    Ok(Certificate {
        version,
        source,
        issuance_accounts,
        distribution_accounts,
        output,
        digest,
    })
}

fn overflow() -> ReportError {
    failed(
        "exact_arithmetic",
        "equity amount exceeds its exact signed range",
    )
}

fn charge(size: &mut usize, bytes: usize, limit: usize) -> Result<(), ReportError> {
    *size = size
        .checked_add(bytes)
        .filter(|size| *size <= limit)
        .ok_or_else(|| {
            failed(
                "bounded_output",
                "equity output exceeds its declared byte bound",
            )
        })?;
    Ok(())
}

#[derive(Default)]
struct Totals {
    opening_contributed: Sum,
    opening_earnings: Sum,
    closing_contributed: Sum,
    closing_earnings: Sum,
    net_income: i128,
    // Issuance, distribution, closing transfer, other equity, prior-period
    // adjustments, in wire-tag order.
    activity: [Sum; 5],
}

fn prior_period_citations(info: &EntryInfo<'_>) -> Result<AdjustmentCitations, ReportError> {
    let case_ordinal = if let Some(raw) = info.case_member {
        let mut r = Reader::new(raw);
        if r.u16("case_member.version")? != 1 {
            return Err(failed(
                "equity_provenance",
                "unsupported case-member version",
            ));
        }
        let ordinal = r.u32("case_member.ordinal")?;
        r.u128("case_member.plan")?;
        r.finish("case member")?;
        if ordinal == 0 {
            return Err(failed("equity_provenance", "case ordinal is zero"));
        }
        Some(ordinal)
    } else {
        None
    };
    let relates_to = if let Some(raw) = info.prior_period_adjustment {
        let mut r = Reader::new(raw);
        if r.u16("prior_period_adjustment.version")? != 1 {
            return Err(failed(
                "equity_provenance",
                "unsupported prior-period-adjustment version",
            ));
        }
        let calendar = text(&mut r, 32, "prior_period_adjustment.calendar")?;
        let code = text(&mut r, 32, "prior_period_adjustment.period")?;
        r.finish("prior-period adjustment")?;
        if calendar.is_empty() || code.is_empty() {
            return Err(failed(
                "equity_provenance",
                "prior-period adjustment names an empty calendar or period",
            ));
        }
        Some((calendar.to_string(), code.to_string()))
    } else {
        None
    };
    Ok((case_ordinal, relates_to))
}

pub(super) fn replay(
    certificate: &Certificate<'_>,
    source: VerifiedRollForward,
    source_digest: [u8; 32],
    schema: &Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, EntryInfo<'_>>,
) -> Result<(VerifiedEquityRollForward, Vec<u8>), ReportError> {
    // Bound all reconstructed bytes before allocating their rows or movements.
    // The source is already bounded, but a certificate may claim a tiny output
    // for a large source. Do not build that output only to reject it afterwards.
    let limit = certificate.output.len().min(MAX_REPORT_BUNDLE_BYTES);
    let mut size = 0;
    charge(
        &mut size,
        16 + REPORT_FORMAT.len() + STATEMENT_FORMAT.len() + 56 + source.label.len(),
        limit,
    )?;
    charge(
        &mut size,
        source
            .units
            .len()
            .checked_mul(if certificate.version == 1 { 212 } else { 244 })
            .ok_or_else(overflow)?,
        limit,
    )?;
    for account in &source.accounts {
        charge(
            &mut size,
            26 + account.code.len() + account.name.len(),
            limit,
        )?;
    }
    let complete: BTreeSet<_> = schema
        .accounts
        .iter()
        .filter(|(_, a)| a.is_leaf && (3..=5).contains(&a.account_type))
        .map(|(id, _)| *id)
        .collect();
    let types: BTreeMap<_, _> = source
        .accounts
        .iter()
        .map(|a| (a.id, a.account_type))
        .collect();
    if types.keys().copied().collect::<BTreeSet<_>>() != complete {
        return Err(failed(
            "equity_completeness",
            "equity source must include every historical equity, revenue and expense leaf, including zero accounts",
        ));
    }
    for id in certificate
        .issuance_accounts
        .iter()
        .chain(&certificate.distribution_accounts)
    {
        if types.get(id) != Some(&3) {
            return Err(failed(
                "equity_selection",
                "owner roles require historical equity posting leaves",
            ));
        }
    }
    let mut totals: BTreeMap<_, Totals> = source
        .units
        .iter()
        .map(|&unit| (unit, Totals::default()))
        .collect();
    for row in &source.rows {
        let total = totals.get_mut(&row.unit_id).ok_or_else(|| {
            failed(
                "equity_selection",
                "equity stock unit is outside its source",
            )
        })?;
        // A single i128::MIN stock cannot be represented by the producer's
        // nonnegative debit/credit balance contract either.
        let opening = row.opening.checked_neg().ok_or_else(overflow)?;
        let closing = row.closing.checked_neg().ok_or_else(overflow)?;
        let (open, close) = if types.get(&row.account_id) == Some(&3) {
            (
                &mut total.opening_contributed,
                &mut total.closing_contributed,
            )
        } else {
            (&mut total.opening_earnings, &mut total.closing_earnings)
        };
        open.add(opening, false).ok_or_else(overflow)?;
        close.add(closing, false).ok_or_else(overflow)?;
    }
    let selected_lineage: BTreeSet<_> = source
        .movements
        .iter()
        .filter(|movement| matches!(movement.bucket.class, 4 | 15))
        .map(|movement| movement.entry_digest)
        .collect();
    let mut metadata = BTreeMap::new();
    if certificate.version >= 2 && !selected_lineage.is_empty() {
        let mut by_identity = BTreeMap::new();
        let mut selected_entries = BTreeMap::new();
        for (&index, info) in infos {
            let Some(envelope) = envelopes.get(index) else {
                continue;
            };
            if envelope.commit_seq > source.known_at {
                continue;
            }
            for identity in info.identities() {
                if by_identity
                    .insert(identity, index)
                    .is_some_and(|old| old != index)
                {
                    return Err(failed(
                        "equity_provenance",
                        "equity ancestry repeats an authenticated entry identity",
                    ));
                }
            }
            if selected_lineage.contains(&envelope.record_digest)
                && selected_entries
                    .insert(envelope.record_digest, index)
                    .is_some()
            {
                return Err(failed(
                    "equity_provenance",
                    "prior-period metadata repeats a selected entry digest",
                ));
            }
        }
        if selected_entries.len() != selected_lineage.len() {
            return Err(failed(
                "equity_provenance",
                "equity movement lacks its authenticated ancestry metadata",
            ));
        }
        // The source bundle carries the complete authenticated prefix, not
        // only movements inside this report's effective window. An earlier
        // PPA therefore remains available when only its reversal is selected.
        let mut lineage = super::statement::Lineage::default();
        for (digest, index) in selected_entries {
            let origin =
                super::statement::origin(index, envelopes, infos, &by_identity, &mut lineage)?;
            if envelopes[origin].class == 15 {
                metadata.insert(digest, (&envelopes[index], &infos[&origin]));
            }
        }
    }
    let mut movements = Vec::new();
    for movement in &source.movements {
        let total = totals.get_mut(&movement.unit_id).ok_or_else(|| {
            failed(
                "equity_selection",
                "equity movement unit is outside its source",
            )
        })?;
        let kind = if movement.bucket.class == 8 {
            EquityActivityKind::ClosingTransfer
        } else if certificate.version >= 2
            && (movement.bucket.class == 15 || metadata.contains_key(&movement.entry_digest))
        {
            if types.get(&movement.account_id) != Some(&3) {
                return Err(failed(
                    "equity_classification",
                    "prior-period adjustments cannot be reported as current income or expense",
                ));
            }
            EquityActivityKind::PriorPeriodAdjustment
        } else if types.get(&movement.account_id) == Some(&3) {
            if certificate
                .issuance_accounts
                .binary_search(&movement.account_id)
                .is_ok()
            {
                EquityActivityKind::Issuance
            } else if certificate
                .distribution_accounts
                .binary_search(&movement.account_id)
                .is_ok()
            {
                EquityActivityKind::Distribution
            } else {
                EquityActivityKind::OtherEquity
            }
        } else {
            total.net_income = total
                .net_income
                .checked_add(movement.credits)
                .and_then(|v| v.checked_sub(movement.debits))
                .ok_or_else(overflow)?;
            continue;
        };
        let sum = &mut total.activity[usize::from(kind.tag() - 1)];
        sum.add(movement.credits, false).ok_or_else(overflow)?;
        sum.add(movement.debits, true).ok_or_else(overflow)?;
        let (case_ordinal, relates_to) = if kind == EquityActivityKind::PriorPeriodAdjustment {
            let (envelope, info) = metadata.get(&movement.entry_digest).ok_or_else(|| {
                failed(
                    "equity_provenance",
                    "prior-period movement lacks its authenticated entry metadata",
                )
            })?;
            if envelope.commit_seq != movement.recorded_seq
                || envelope.effective_day != Some(movement.effective_day)
                || envelope.class != movement.bucket.class
            {
                return Err(failed(
                    "equity_provenance",
                    "prior-period movement differs from its authenticated coordinate",
                ));
            }
            prior_period_citations(info)?
        } else {
            (None, None)
        };
        let extra = if certificate.version == 1 {
            0
        } else {
            2 + if case_ordinal.is_some() { 4 } else { 0 }
                + relates_to
                    .as_ref()
                    .map_or(0, |(calendar, code)| 8 + calendar.len() + code.len())
        };
        charge(&mut size, 103 + extra, limit)?;
        movements.push(EquityMovement {
            entry_digest: movement.entry_digest,
            leg_index: movement.leg_index,
            recorded_seq: movement.recorded_seq,
            effective_day: movement.effective_day,
            class: movement.bucket.class,
            kind,
            account_id: movement.account_id,
            unit_id: movement.unit_id,
            debits: movement.debits,
            credits: movement.credits,
            case_ordinal,
            relates_to,
        });
    }
    let mut units = Vec::with_capacity(totals.len());
    for (unit_id, total) in totals {
        let opening_contributed_equity = total.opening_contributed.value().ok_or_else(overflow)?;
        let opening_unclosed_earnings = total.opening_earnings.value().ok_or_else(overflow)?;
        let closing_contributed_equity = total.closing_contributed.value().ok_or_else(overflow)?;
        let closing_unclosed_earnings = total.closing_earnings.value().ok_or_else(overflow)?;
        let opening_total_equity = opening_contributed_equity
            .checked_add(opening_unclosed_earnings)
            .ok_or_else(overflow)?;
        let closing_total_equity = closing_contributed_equity
            .checked_add(closing_unclosed_earnings)
            .ok_or_else(overflow)?;
        let [
            issuances,
            distributions,
            closing_transfers_net,
            other_equity_movements,
            prior_period_adjustments,
        ] = total
            .activity
            .map(Sum::value)
            .map(|v| v.ok_or_else(overflow));
        let (
            issuances,
            distributions,
            closing_transfers_net,
            other_equity_movements,
            prior_period_adjustments,
        ) = (
            issuances?,
            distributions?,
            closing_transfers_net?,
            other_equity_movements?,
            prior_period_adjustments?,
        );
        let opening_equity_as_adjusted = opening_total_equity
            .checked_add(prior_period_adjustments)
            .ok_or_else(overflow)?;
        if closing_transfers_net != 0 {
            return Err(failed(
                "equity_identity",
                "closing transfers do not conserve total equity",
            ));
        }
        let mut change = Sum::default();
        for part in [
            prior_period_adjustments,
            total.net_income,
            issuances,
            distributions,
            other_equity_movements,
        ] {
            change.add(part, false).ok_or_else(overflow)?;
        }
        let net_equity_change = change.value().ok_or_else(overflow)?;
        let mut tie = Sum::default();
        tie.add(opening_total_equity, false).ok_or_else(overflow)?;
        tie.add(net_equity_change, false).ok_or_else(overflow)?;
        tie.add(closing_total_equity, true).ok_or_else(overflow)?;
        let equity_tie_out_residual = tie.value().ok_or_else(overflow)?;
        if equity_tie_out_residual != 0 {
            return Err(failed(
                "equity_identity",
                "equity movements do not reconcile opening and closing stock",
            ));
        }
        units.push(EquityRollForwardUnit {
            unit_id,
            opening_contributed_equity,
            opening_unclosed_earnings,
            opening_total_equity,
            prior_period_adjustments,
            opening_equity_as_adjusted,
            net_income: total.net_income,
            issuances,
            distributions,
            other_equity_movements,
            closing_transfers_net,
            net_equity_change,
            closing_contributed_equity,
            closing_unclosed_earnings,
            closing_total_equity,
            equity_tie_out_residual,
        });
    }
    let report = VerifiedEquityRollForward {
        format_version: certificate.version,
        book_id: source.book_id,
        known_at: source.known_at,
        label: source.label,
        effective_from: source.effective_from,
        effective_through: source.effective_through,
        source_certificate_digest: source_digest,
        issuance_accounts: certificate.issuance_accounts.clone(),
        distribution_accounts: certificate.distribution_accounts.clone(),
        accounts: source.accounts,
        units,
        movements,
    };
    let output = encode(&report);
    if output.len() > MAX_REPORT_BUNDLE_BYTES || output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "equity amounts, account metadata, owner classifications or complete movement citations differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn encode(report: &VerifiedEquityRollForward) -> Vec<u8> {
    let mut statement = Writer::default();
    statement
        .fixed(if report.format_version == 1 {
            STATEMENT_FORMAT_V1
        } else {
            STATEMENT_FORMAT
        })
        .fixed(&report.book_id)
        .fixed(&[0; 16])
        .u64(report.known_at)
        .bytes(report.label.as_bytes())
        .i32(report.effective_from)
        .i32(report.effective_through)
        .count(report.units.len());
    for unit in &report.units {
        statement.u32(unit.unit_id);
        for value in [
            unit.opening_contributed_equity,
            unit.opening_unclosed_earnings,
            unit.opening_total_equity,
        ] {
            statement.i128(value);
        }
        if report.format_version >= 2 {
            statement
                .i128(unit.prior_period_adjustments)
                .i128(unit.opening_equity_as_adjusted);
        }
        for value in [
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
        ] {
            statement.i128(value);
        }
    }
    let mut w = Writer::default();
    w.bytes(if report.format_version == 1 {
        REPORT_FORMAT_V1
    } else {
        REPORT_FORMAT
    })
    .bytes(&statement.buf)
    .count(report.accounts.len());
    for account in &report.accounts {
        w.u128(account.id)
            .bytes(account.code.as_bytes())
            .bytes(account.name.as_bytes())
            .u8(account.account_type)
            .u8(u8::from(account.is_leaf));
    }
    w.count(report.movements.len());
    for movement in &report.movements {
        w.fixed(&movement.entry_digest)
            .u32(movement.leg_index)
            .u64(movement.recorded_seq)
            .i32(movement.effective_day)
            .u16(movement.class)
            .u8(movement.kind.tag())
            .u128(movement.account_id)
            .u32(movement.unit_id)
            .i128(movement.debits)
            .i128(movement.credits);
        if report.format_version >= 2 {
            w.u8(u8::from(movement.case_ordinal.is_some()));
            if let Some(case) = movement.case_ordinal {
                w.u32(case);
            }
            w.u8(u8::from(movement.relates_to.is_some()));
            if let Some((calendar, code)) = &movement.relates_to {
                w.bytes(calendar.as_bytes()).bytes(code.as_bytes());
            }
        }
    }
    w.buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::metadata::Account;
    use crate::report::roll_forward::{RollForwardBucket, RollForwardMovement, RollForwardRow};

    // Hand-computed: opening 1,000 + income 200 + issuance 50 - dividend 75
    // = closing equity 1,175. Closing transfers contribute exactly zero.
    fn fixture() -> (Schema, VerifiedRollForward, VerifiedEquityRollForward) {
        let mut schema = Schema::default();
        let accounts: Vec<_> = [(30, 3), (31, 3), (40, 4), (60, 5), (61, 5)]
            .into_iter()
            .map(|(id, kind)| {
                schema.accounts.insert(
                    id,
                    Account {
                        code: id.to_string(),
                        name: format!("Account {id}"),
                        account_type: kind,
                        normal_balance: u8::from(kind != 5),
                        is_leaf: true,
                        unit_policy: -1,
                        limit: None,
                        created_at: 1,
                    },
                );
                RollForwardAccount {
                    id,
                    code: id.to_string(),
                    name: format!("Account {id}"),
                    account_type: kind,
                    is_leaf: true,
                }
            })
            .collect();
        let bucket = |class| RollForwardBucket {
            class,
            reason_code: String::new(),
            rule_digest: None,
        };
        let movements: Vec<_> = [
            (30, 1, false, 50),
            (31, 1, true, 75),
            (40, 1, false, 300),
            (60, 1, true, 100),
            (40, 8, true, 300),
            (60, 8, false, 100),
            (30, 8, false, 200),
        ]
        .into_iter()
        .enumerate()
        .map(
            |(i, (account_id, class, debit, amount))| RollForwardMovement {
                entry_digest: [i as u8 + 1; 32],
                leg_index: 0,
                recorded_seq: i as u64 + 2,
                effective_day: 15,
                account_id,
                unit_id: 1,
                bucket: bucket(class),
                debits: if debit { amount } else { 0 },
                credits: if debit { 0 } else { amount },
            },
        )
        .collect();
        let rows = [
            (30, -1_000, -50, -200, -1_250),
            (31, 0, 75, 0, 75),
            (40, 0, -300, 300, 0),
            (60, 0, 100, -100, 0),
            (61, 0, 0, 0, 0),
        ]
        .into_iter()
        .flat_map(
            |(account_id, opening, ordinary, closing_transfer, closing)| {
                [
                    RollForwardRow {
                        account_id,
                        unit_id: 1,
                        opening,
                        activity: vec![ordinary, closing_transfer],
                        net_change: closing - opening,
                        closing,
                    },
                    RollForwardRow {
                        account_id,
                        unit_id: 2,
                        opening: 0,
                        activity: vec![0, 0],
                        net_change: 0,
                        closing: 0,
                    },
                ]
            },
        )
        .collect();
        let source = VerifiedRollForward {
            book_id: [7; 16],
            known_at: 10,
            label: "Equity".into(),
            effective_from: 10,
            effective_through: 20,
            source_certificate_digest: [8; 32],
            accounts: accounts.clone(),
            units: vec![1, 2],
            buckets: vec![bucket(1), bucket(8)],
            rows,
            movements: movements.clone(),
        };
        let expected = VerifiedEquityRollForward {
            format_version: 1,
            book_id: [7; 16],
            known_at: 10,
            label: "Equity".into(),
            effective_from: 10,
            effective_through: 20,
            source_certificate_digest: [9; 32],
            issuance_accounts: vec![30],
            distribution_accounts: vec![31],
            accounts,
            units: vec![
                EquityRollForwardUnit {
                    unit_id: 1,
                    opening_contributed_equity: 1_000,
                    opening_unclosed_earnings: 0,
                    opening_total_equity: 1_000,
                    prior_period_adjustments: 0,
                    opening_equity_as_adjusted: 1_000,
                    net_income: 200,
                    issuances: 50,
                    distributions: -75,
                    other_equity_movements: 0,
                    closing_transfers_net: 0,
                    net_equity_change: 175,
                    closing_contributed_equity: 1_175,
                    closing_unclosed_earnings: 0,
                    closing_total_equity: 1_175,
                    equity_tie_out_residual: 0,
                },
                EquityRollForwardUnit {
                    unit_id: 2,
                    opening_contributed_equity: 0,
                    opening_unclosed_earnings: 0,
                    opening_total_equity: 0,
                    prior_period_adjustments: 0,
                    opening_equity_as_adjusted: 0,
                    net_income: 0,
                    issuances: 0,
                    distributions: 0,
                    other_equity_movements: 0,
                    closing_transfers_net: 0,
                    net_equity_change: 0,
                    closing_contributed_equity: 0,
                    closing_unclosed_earnings: 0,
                    closing_total_equity: 0,
                    equity_tie_out_residual: 0,
                },
            ],
            movements: [0, 1, 4, 5, 6]
                .into_iter()
                .map(|i| {
                    let m = &movements[i];
                    EquityMovement {
                        entry_digest: m.entry_digest,
                        leg_index: m.leg_index,
                        recorded_seq: m.recorded_seq,
                        effective_day: m.effective_day,
                        class: m.bucket.class,
                        kind: match i {
                            0 => EquityActivityKind::Issuance,
                            1 => EquityActivityKind::Distribution,
                            _ => EquityActivityKind::ClosingTransfer,
                        },
                        account_id: m.account_id,
                        unit_id: m.unit_id,
                        debits: m.debits,
                        credits: m.credits,
                        case_ordinal: None,
                        relates_to: None,
                    }
                })
                .collect(),
        };
        (schema, source, expected)
    }

    fn certificate(output: &[u8]) -> Certificate<'_> {
        Certificate {
            version: 1,
            source: &[],
            issuance_accounts: vec![30],
            distribution_accounts: vec![31],
            output,
            digest: [4; 32],
        }
    }

    fn replay(
        certificate: &Certificate<'_>,
        source: VerifiedRollForward,
        source_digest: [u8; 32],
        schema: &Schema,
    ) -> Result<(VerifiedEquityRollForward, Vec<u8>), ReportError> {
        super::replay(
            certificate,
            source,
            source_digest,
            schema,
            &[],
            &BTreeMap::new(),
        )
    }

    #[test]
    fn equity_certificate_versions_bind_their_own_digest_domains() {
        let (_, _, mut expected) = fixture();
        // This exercises the outer decoder, independently of source replay.
        // The nested source marker is enough for its format discrimination.
        let mut source = Writer::default();
        source.bytes(crate::report::roll_forward::CERTIFICATE_FORMAT);
        let frame = |format: &[u8], domain: &[u8], output: &[u8]| {
            let mut w = Writer::default();
            w.bytes(format)
                .bytes(&source.buf)
                .count(1)
                .u128(30)
                .count(1)
                .u128(31)
                .bytes(output);
            let digest = hash_parts(domain, &[&(w.buf.len() as u32).to_le_bytes(), &w.buf]);
            w.fixed(&digest);
            w.buf
        };
        for (version, format, domain, wrong_domain) in [
            (1, CERTIFICATE_FORMAT_V1, DIGEST_DOMAIN_V1, DIGEST_DOMAIN),
            (2, CERTIFICATE_FORMAT, DIGEST_DOMAIN, DIGEST_DOMAIN_V1),
        ] {
            expected.format_version = version;
            let output = encode(&expected);
            let bytes = frame(format, domain, &output);
            assert!(recognizes(&bytes));
            let decoded = decode(&bytes).unwrap();
            assert_eq!(decoded.version, version);
            assert_eq!(decoded.source, source.buf);
            assert_eq!(decoded.issuance_accounts, [30]);
            assert_eq!(decoded.distribution_accounts, [31]);
            assert_eq!(decoded.output, output);

            let substituted = frame(format, wrong_domain, &output);
            assert_eq!(
                decode(&substituted).err().unwrap().predicate,
                "certificate_digest"
            );
            let mut changed_version = bytes.clone();
            changed_version[4 + format.len() - 1] = if version == 1 { b'2' } else { b'1' };
            assert_eq!(
                decode(&changed_version).err().unwrap().predicate,
                "certificate_digest"
            );
        }
        let unsupported = frame(b"fa:equity-roll-forward-certificate:v3", DIGEST_DOMAIN, &[]);
        assert!(!recognizes(&unsupported));
        assert_eq!(
            decode(&unsupported).err().unwrap().predicate,
            "supported_report"
        );
    }

    #[test]
    fn independent_equity_replay_conserves_closing_and_owner_changes() {
        let (schema, source, expected) = fixture();
        let bytes = encode(&expected);
        let (actual, output) = replay(&certificate(&bytes), source, [9; 32], &schema).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(output, bytes);
    }

    #[test]
    fn independent_equity_refuses_omitted_zero_leaves_roles_and_changed_citations() {
        let (schema, source, expected) = fixture();
        let bytes = encode(&expected);
        let mut incomplete = source.clone();
        incomplete.accounts.retain(|a| a.id != 61);
        incomplete.rows.retain(|r| r.account_id != 61);
        assert_eq!(
            replay(&certificate(&bytes), incomplete, [9; 32], &schema)
                .unwrap_err()
                .predicate,
            "equity_completeness"
        );
        let mut invalid_role = certificate(&bytes);
        invalid_role.issuance_accounts = vec![40];
        assert_eq!(
            replay(&invalid_role, source.clone(), [9; 32], &schema)
                .unwrap_err()
                .predicate,
            "equity_selection"
        );
        let mut changed = expected;
        changed.movements[0].leg_index += 1;
        let wrong = encode(&changed);
        assert_eq!(
            replay(&certificate(&wrong), source, [9; 32], &schema)
                .unwrap_err()
                .predicate,
            "report_recomputation"
        );
    }

    #[test]
    fn independent_equity_refuses_unbalanced_closes_overflow_and_unbounded_output() {
        let (schema, source, expected) = fixture();
        let bytes = encode(&expected);
        let mut close = source.clone();
        close.movements[6].credits += 1;
        assert_eq!(
            replay(&certificate(&bytes), close, [9; 32], &schema)
                .unwrap_err()
                .predicate,
            "equity_identity"
        );
        let mut overflow = source.clone();
        overflow.rows[0].opening = i128::MIN;
        assert_eq!(
            replay(&certificate(&bytes), overflow, [9; 32], &schema)
                .unwrap_err()
                .predicate,
            "exact_arithmetic"
        );
        assert_eq!(
            replay(&certificate(&[]), source, [9; 32], &schema)
                .unwrap_err()
                .predicate,
            "bounded_output"
        );
    }

    fn with_prior_period_adjustment(
        mut source: VerifiedRollForward,
        mut expected: VerifiedEquityRollForward,
    ) -> (VerifiedRollForward, VerifiedEquityRollForward) {
        source.movements.push(RollForwardMovement {
            entry_digest: [9; 32],
            leg_index: 1,
            recorded_seq: 9,
            effective_day: 10,
            account_id: 30,
            unit_id: 1,
            bucket: RollForwardBucket {
                class: 15,
                reason_code: String::new(),
                rule_digest: None,
            },
            debits: 80,
            credits: 0,
        });
        let row = source
            .rows
            .iter_mut()
            .find(|row| row.account_id == 30 && row.unit_id == 1)
            .unwrap();
        row.closing += 80;
        row.net_change += 80;
        expected.format_version = 2;
        expected.units[0].prior_period_adjustments = -80;
        expected.units[0].opening_equity_as_adjusted = 920;
        expected.units[0].net_equity_change = 95;
        expected.units[0].closing_contributed_equity = 1_095;
        expected.units[0].closing_total_equity = 1_095;
        expected.movements.push(EquityMovement {
            entry_digest: [9; 32],
            leg_index: 1,
            recorded_seq: 9,
            effective_day: 10,
            class: 15,
            kind: EquityActivityKind::PriorPeriodAdjustment,
            account_id: 30,
            unit_id: 1,
            debits: 80,
            credits: 0,
            case_ordinal: Some(7),
            relates_to: Some(("gregorian".into(), "FY2025".into())),
        });
        (source, expected)
    }

    fn prior_period_entry_info<'a>(case: &'a [u8], prior: &'a [u8]) -> EntryInfo<'a> {
        EntryInfo {
            schema: None,
            time_tick: None,
            period: None,
            resolution: None,
            supersession: Vec::new(),
            supersession_reasons: Vec::new(),
            rule_version_oid: None,
            has_fx_revaluation_basis: false,
            obligation_maturity: None,
            case_member: Some(case),
            prior_period_adjustment: Some(prior),
            evidence: Vec::new(),
            identity: 9,
            legacy_identity: None,
        }
    }

    fn prior_period_envelope() -> LeafEnvelope {
        LeafEnvelope {
            kind: crate::envelope::KIND_ENTRY,
            book_id: [7; 16],
            branch_id: [0; 16],
            commit_seq: 9,
            within_commit_ordinal: 0,
            record_digest: [9; 32],
            class: 15,
            effective_day: Some(10),
            account_vids: vec![30],
            unit_ids: vec![1],
        }
    }

    #[test]
    fn prior_period_equity_line_recomputes_independently_with_case_and_period_citations() {
        let (schema, source, expected) = fixture();
        let (source, expected) = with_prior_period_adjustment(source, expected);
        let output = encode(&expected);
        let mut cert = certificate(&output);
        cert.version = 2;
        let mut case = Writer::default();
        case.u16(1).u32(7).u128(99);
        let mut prior = Writer::default();
        prior.u16(1).bytes(b"gregorian").bytes(b"FY2025");
        let infos = BTreeMap::from([(0, prior_period_entry_info(&case.buf, &prior.buf))]);
        let (actual, bytes) = super::replay(
            &cert,
            source.clone(),
            [9; 32],
            &schema,
            &[prior_period_envelope()],
            &infos,
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(bytes, output);
        assert_eq!(actual.units[0].opening_total_equity, 1_000);
        assert_eq!(actual.units[0].prior_period_adjustments, -80);
        assert_eq!(actual.units[0].opening_equity_as_adjusted, 920);
        assert_eq!(actual.units[0].net_income, 200);
        assert_eq!(actual.units[0].issuances, 50);
        assert_eq!(actual.units[0].closing_total_equity, 1_095);
        assert_eq!(actual.units[1].prior_period_adjustments, 0);

        for mutation in 0..4 {
            let mut changed = expected.clone();
            match mutation {
                0 => changed.movements.last_mut().unwrap().case_ordinal = Some(8),
                1 => changed.movements.last_mut().unwrap().relates_to = None,
                2 => changed.units[0].prior_period_adjustments -= 1,
                3 => {
                    changed.movements.last_mut().unwrap().kind = EquityActivityKind::Issuance;
                    changed.units[0].prior_period_adjustments = 0;
                    changed.units[0].opening_equity_as_adjusted = 1_000;
                    changed.units[0].issuances = -30;
                }
                _ => unreachable!(),
            }
            let wrong = encode(&changed);
            let mut cert = certificate(&wrong);
            cert.version = 2;
            assert!(
                super::replay(
                    &cert,
                    source.clone(),
                    [9; 32],
                    &schema,
                    &[prior_period_envelope()],
                    &infos,
                )
                .is_err(),
                "mutation {mutation}"
            );
        }
        assert_eq!(
            super::replay(&cert, source.clone(), [9; 32], &schema, &[], &infos)
                .unwrap_err()
                .predicate,
            "equity_provenance"
        );
        let mut missing_terms =
            BTreeMap::from([(0, prior_period_entry_info(&case.buf, &prior.buf))]);
        missing_terms.get_mut(&0).unwrap().prior_period_adjustment = None;
        assert!(
            super::replay(
                &cert,
                source,
                [9; 32],
                &schema,
                &[prior_period_envelope()],
                &missing_terms,
            )
            .is_err()
        );
    }

    #[test]
    fn prior_period_reversals_inherit_authenticated_case_and_period_through_the_chain() {
        let (schema, source, expected) = fixture();
        let (mut source, mut expected) = with_prior_period_adjustment(source, expected);
        let mut case = Writer::default();
        case.u16(1).u32(7).u128(99);
        let mut prior = Writer::default();
        prior.u16(1).bytes(b"gregorian").bytes(b"FY2025");
        let mut infos = BTreeMap::from([(0, prior_period_entry_info(&case.buf, &prior.buf))]);
        let mut envelopes = vec![prior_period_envelope()];
        for ordinal in 1..=2u8 {
            let delta = if ordinal == 1 { 80 } else { -80 };
            let identity = 9 + ordinal;
            let recorded_seq = u64::from(identity);
            let effective_day = 10 + 2 * i32::from(ordinal);
            let mut info = prior_period_entry_info(&case.buf, &prior.buf);
            info.identity = u128::from(identity);
            info.supersession = vec![(u128::from(identity - 1), [identity - 1; 32], 1)];
            info.case_member = None;
            info.prior_period_adjustment = None;
            infos.insert(usize::from(ordinal), info);
            let mut envelope = prior_period_envelope();
            envelope.record_digest = [identity; 32];
            envelope.class = 4;
            envelope.commit_seq = recorded_seq;
            envelope.effective_day = Some(effective_day);
            envelopes.push(envelope);
            source.known_at = recorded_seq;
            expected.known_at = recorded_seq;
            let movement = RollForwardMovement {
                entry_digest: [identity; 32],
                leg_index: 1,
                recorded_seq,
                effective_day,
                account_id: 30,
                unit_id: 1,
                bucket: RollForwardBucket {
                    class: 4,
                    reason_code: String::new(),
                    rule_digest: None,
                },
                debits: if delta < 0 { -delta } else { 0 },
                credits: if delta > 0 { delta } else { 0 },
            };
            source.movements.push(movement.clone());
            let row = source
                .rows
                .iter_mut()
                .find(|row| row.account_id == 30 && row.unit_id == 1)
                .unwrap();
            row.closing -= delta;
            row.net_change -= delta;
            let unit = &mut expected.units[0];
            unit.prior_period_adjustments += delta;
            unit.opening_equity_as_adjusted += delta;
            unit.net_equity_change += delta;
            unit.closing_contributed_equity += delta;
            unit.closing_total_equity += delta;
            expected.movements.push(EquityMovement {
                entry_digest: movement.entry_digest,
                leg_index: movement.leg_index,
                recorded_seq,
                effective_day,
                class: 4,
                kind: EquityActivityKind::PriorPeriodAdjustment,
                account_id: 30,
                unit_id: 1,
                debits: movement.debits,
                credits: movement.credits,
                case_ordinal: Some(7),
                relates_to: Some(("gregorian".into(), "FY2025".into())),
            });
            let output = encode(&expected);
            let mut cert = certificate(&output);
            cert.version = 2;
            let (actual, bytes) =
                super::replay(&cert, source.clone(), [9; 32], &schema, &envelopes, &infos).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(bytes, output);
            assert_eq!(actual.units[0].issuances, 50);
            assert_eq!(actual.units[0].other_equity_movements, 0);
            assert_eq!(
                actual.units[0].prior_period_adjustments,
                if ordinal == 1 { 0 } else { -80 }
            );

            // Even a repaired report with matching closing equity cannot
            // relabel the reversal as an owner contribution.
            let mut changed = expected.clone();
            changed.units[0].prior_period_adjustments -= delta;
            changed.units[0].opening_equity_as_adjusted -= delta;
            changed.units[0].issuances += delta;
            let moved = changed.movements.last_mut().unwrap();
            moved.kind = EquityActivityKind::Issuance;
            moved.case_ordinal = None;
            moved.relates_to = None;
            let wrong = encode(&changed);
            let mut wrong_cert = certificate(&wrong);
            wrong_cert.version = 2;
            assert!(
                super::replay(
                    &wrong_cert,
                    source.clone(),
                    [9; 32],
                    &schema,
                    &envelopes,
                    &infos,
                )
                .is_err()
            );
        }
        let output = encode(&expected);
        let mut cert = certificate(&output);
        cert.version = 2;
        let valid = infos[&1].supersession[0];
        for invalid in [
            (999, valid.1, 1),
            (valid.0, [99; 32], 1),
            (valid.0, valid.1, 2),
        ] {
            infos.get_mut(&1).unwrap().supersession[0] = invalid;
            assert_eq!(
                super::replay(&cert, source.clone(), [9; 32], &schema, &envelopes, &infos,)
                    .unwrap_err()
                    .predicate,
                "entry_lineage"
            );
        }
        infos.get_mut(&1).unwrap().supersession[0] = valid;

        // Historical certificates retain their original owner-role law,
        // including for these exact same PPA and reversal payloads.
        expected.format_version = 1;
        let unit = &mut expected.units[0];
        unit.issuances += unit.prior_period_adjustments;
        unit.prior_period_adjustments = 0;
        unit.opening_equity_as_adjusted = unit.opening_total_equity;
        for movement in &mut expected.movements {
            if movement.kind == EquityActivityKind::PriorPeriodAdjustment {
                movement.kind = EquityActivityKind::Issuance;
                movement.case_ordinal = None;
                movement.relates_to = None;
            }
        }
        let legacy = encode(&expected);
        let (actual, bytes) = replay(&certificate(&legacy), source, [9; 32], &schema).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(bytes, legacy);
    }

    #[test]
    fn prior_period_equity_v1_replay_preserves_historical_owner_classification() {
        let (schema, source, expected) = fixture();
        let (source, mut legacy) = with_prior_period_adjustment(source, expected);
        legacy.format_version = 1;
        legacy.units[0].prior_period_adjustments = 0;
        legacy.units[0].opening_equity_as_adjusted = 1_000;
        legacy.units[0].issuances = -30;
        let movement = legacy.movements.last_mut().unwrap();
        movement.kind = EquityActivityKind::Issuance;
        movement.case_ordinal = None;
        movement.relates_to = None;
        let output = encode(&legacy);
        let (actual, bytes) = replay(&certificate(&output), source, [9; 32], &schema).unwrap();
        assert_eq!(actual, legacy);
        assert_eq!(bytes, output);
        assert_eq!(actual.units[0].prior_period_adjustments, 0);
        assert_eq!(actual.units[0].issuances, -30);
    }
}
