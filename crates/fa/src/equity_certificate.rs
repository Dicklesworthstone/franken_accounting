//! Retained-history certificates for the complete Statement of Changes in Equity.
//!
//! The lead-schedule certificate proves the native inputs. This outer transcript
//! also binds the independently chosen issuance/distribution roles and every
//! rendered amount, account and movement citation. It is not an outsider proof.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_journal::{Refusal, exit};
use fa_model::{Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{
    AsyncBook, BookError, EquityActivityKind, EquityRollForward, EquityRollForwardReport,
    EquityRollForwardRequest, Outcome, RollForwardCertificate,
};

pub const EQUITY_CERTIFICATE_FORMAT: &[u8] = b"fa:equity-roll-forward-certificate:v2";
pub const EQUITY_REPORT_FORMAT: &str = "fa:equity-roll-forward-report:v2";
pub(crate) const LEGACY_EQUITY_CERTIFICATE_FORMAT: &[u8] = b"fa:equity-roll-forward-certificate:v1";
const LEGACY_EQUITY_REPORT_FORMAT: &str = "fa:equity-roll-forward-report:v1";
pub const MAX_EQUITY_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"fa:equity-roll-forward-certificate-digest:v2";
const LEGACY_DIGEST_DOMAIN: &[u8] = b"fa:equity-roll-forward-certificate-digest:v1";
const MAX_SCOPE: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardCertificate {
    legacy: bool,
    source: RollForwardCertificate,
    request: EquityRollForwardRequest,
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedEquityRollForward {
    pub report: EquityRollForwardReport,
    pub certificate: EquityRollForwardCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §12.1 / §13.6 (complete equity roll-forward and independent classification replay)",
        "replay the original equity certificate with the independently retained fixed prefix, dates, units and issuance/distribution accounts using fa replay C:<oid> --expect '<JSON>'",
    )
}

fn normalize(
    request: &EquityRollForwardRequest,
    at: CommitSeq,
) -> Result<EquityRollForwardRequest, Refusal> {
    if request.units.is_empty()
        || request.units.len() > MAX_SCOPE
        || request.issuance_accounts.len() > MAX_SCOPE
        || request.distribution_accounts.len() > MAX_SCOPE
        || request.label.trim().is_empty()
        || request.label.len() > 256
        || request.effective_from > request.effective_through
    {
        return Err(invalid("invalid or excessive equity scope, label or dates"));
    }
    let units: BTreeSet<_> = request.units.iter().copied().collect();
    let issuance: BTreeSet<_> = request.issuance_accounts.iter().copied().collect();
    let distribution: BTreeSet<_> = request.distribution_accounts.iter().copied().collect();
    if units.len() != request.units.len()
        || issuance.len() != request.issuance_accounts.len()
        || distribution.len() != request.distribution_accounts.len()
        || !issuance.is_disjoint(&distribution)
    {
        return Err(invalid(
            "equity units and role accounts must be distinct; an account cannot have both roles",
        ));
    }
    Ok(EquityRollForwardRequest {
        units: units.into_iter().collect(),
        label: request.label.clone(),
        effective_from: request.effective_from,
        effective_through: request.effective_through,
        known_at: Some(at),
        issuance_accounts: issuance.into_iter().collect(),
        distribution_accounts: distribution.into_iter().collect(),
    })
}

impl EquityRollForwardReport {
    /// Exact statement, chart presentation and every classified journal leg.
    /// The nested source proves the net-income legs as well as these equity legs.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        self.canonical_bytes_for(false)
    }

    pub(crate) fn canonical_bytes_for(&self, legacy: bool) -> Result<Vec<u8>, Refusal> {
        let statement = if legacy {
            self.statement
                .canonical_bytes_v1()
                .map_err(|e| invalid(e.to_string()))?
        } else {
            self.statement
                .canonical_bytes()
                .map_err(|e| invalid(e.to_string()))?
        };
        let mut w = Writer::new();
        w.bytes(if legacy {
            LEGACY_EQUITY_REPORT_FORMAT.as_bytes()
        } else {
            EQUITY_REPORT_FORMAT.as_bytes()
        })
        .bytes(&statement);
        w.list(&self.accounts, |w, account| {
            w.u128(account.id)
                .str(&account.code)
                .str(&account.name)
                .u8(account.account_type)
                .u8(u8::from(account.is_leaf));
        });
        w.list(&self.movements, |w, movement| {
            w.fixed(&movement.entry_digest)
                .u32(movement.leg_index)
                .u64(movement.recorded_seq)
                .i32(movement.effective_day.0)
                .u16(movement.class.0)
                .u8(match movement.kind {
                    EquityActivityKind::Issuance => 1,
                    EquityActivityKind::Distribution => 2,
                    EquityActivityKind::ClosingTransfer => 3,
                    EquityActivityKind::OtherEquity => 4,
                    EquityActivityKind::PriorPeriodAdjustment => 5,
                })
                .u128(movement.account_id)
                .u32(movement.unit_id)
                .i128(movement.debits)
                .i128(movement.credits);
            if !legacy {
                w.opt(movement.case_ordinal.as_ref(), |w, ordinal| {
                    w.u32(*ordinal);
                })
                .opt(movement.relates_to.as_ref(), |w, period| {
                    w.str(&period.calendar).str(&period.code);
                });
            }
        });
        let bytes = w.finish().map_err(|e| invalid(e.to_string()))?;
        if bytes.len() > MAX_EQUITY_CERTIFICATE_BYTES {
            return Err(invalid("equity output exceeds the 64 MiB limit"));
        }
        Ok(bytes)
    }
}

impl EquityRollForwardCertificate {
    pub(crate) fn is_legacy(&self) -> bool {
        self.legacy
    }

    fn format(&self) -> &'static [u8] {
        if self.legacy {
            LEGACY_EQUITY_CERTIFICATE_FORMAT
        } else {
            EQUITY_CERTIFICATE_FORMAT
        }
    }

    fn digest_domain(&self) -> &'static [u8] {
        if self.legacy {
            LEGACY_DIGEST_DOMAIN
        } else {
            DIGEST_DOMAIN
        }
    }

    #[must_use]
    pub fn source_certificate(&self) -> &RollForwardCertificate {
        &self.source
    }
    #[must_use]
    pub fn request(&self) -> &EquityRollForwardRequest {
        &self.request
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at()
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let scope = self.source.request();
        if normalize(&self.request, self.known_at())? != self.request
            || self.request.units != scope.units
            || self.request.label != scope.label
            || self.request.effective_from != scope.effective_from
            || self.request.effective_through != scope.effective_through
            || self.request.known_at != scope.known_at
        {
            return Err(invalid("equity request differs from its source coordinate"));
        }
        let mut output = Reader::new(&self.output);
        if output
            .bytes(64, "equity output format")
            .map_err(|e| invalid(e.to_string()))?
            != if self.legacy {
                LEGACY_EQUITY_REPORT_FORMAT.as_bytes()
            } else {
                EQUITY_REPORT_FORMAT.as_bytes()
            }
        {
            return Err(invalid("unsupported equity output format"));
        }
        let statement_bytes = output
            .bytes(MAX_EQUITY_CERTIFICATE_BYTES, "equity statement")
            .map_err(|e| invalid(e.to_string()))?;
        let statement_format: &[u8] = if self.legacy {
            b"fa:equity-roll-forward:v1"
        } else {
            b"fa:equity-roll-forward:v2"
        };
        if !statement_bytes.starts_with(statement_format) {
            return Err(invalid(
                "equity statement version differs from its certificate",
            ));
        }
        let statement =
            EquityRollForward::decode(statement_bytes).map_err(|e| invalid(e.to_string()))?;
        if statement.book_id != self.source.source_certificate().book_id
            || statement.branch_id != self.source.source_certificate().branch_id
            || statement.known_at != self.known_at().0
            || statement.label != self.request.label
            || statement.effective_from != self.request.effective_from
            || statement.effective_through != self.request.effective_through
            || statement
                .units
                .iter()
                .map(|u| u.unit_id)
                .collect::<Vec<_>>()
                != self.request.units
        {
            return Err(invalid("equity output header differs from its request"));
        }
        let source = self.source.canonical_bytes()?;
        let size = self
            .request
            .issuance_accounts
            .len()
            .checked_add(self.request.distribution_accounts.len())
            .and_then(|n| n.checked_mul(16))
            .and_then(|n| n.checked_add(source.len()))
            .and_then(|n| n.checked_add(self.output.len()))
            .and_then(|n| n.checked_add(EQUITY_CERTIFICATE_FORMAT.len() + 52))
            .filter(|n| *n <= MAX_EQUITY_CERTIFICATE_BYTES)
            .ok_or_else(|| invalid("equity certificate exceeds the 64 MiB limit"))?;
        let mut w = Writer::with_capacity(size);
        w.bytes(self.format())
            .bytes(&source)
            .list(&self.request.issuance_accounts, |w, id| {
                w.u128(id.0);
            })
            .list(&self.request.distribution_accounts, |w, id| {
                w.u128(id.0);
            })
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(
        source: RollForwardCertificate,
        request: EquityRollForwardRequest,
        report: &EquityRollForwardReport,
    ) -> Result<Self, Refusal> {
        let mut certificate = Self {
            legacy: false,
            source,
            request,
            output: report.canonical_bytes()?,
            digest: [0; 32],
        };
        certificate.digest =
            domain_digest(certificate.digest_domain(), &[&certificate.body_bytes()?]);
        Ok(certificate)
    }

    /// Decode checks bounded framing and public content integrity, never truth.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_EQUITY_CERTIFICATE_BYTES {
            return Err(invalid("equity certificate exceeds the 64 MiB limit"));
        }
        let mut r = Reader::new(bytes);
        let legacy = match r
            .bytes(64, "equity certificate format")
            .map_err(|e| invalid(e.to_string()))?
        {
            EQUITY_CERTIFICATE_FORMAT => false,
            LEGACY_EQUITY_CERTIFICATE_FORMAT => true,
            _ => return Err(invalid("unsupported equity certificate format")),
        };
        let source = RollForwardCertificate::decode(
            r.bytes(MAX_EQUITY_CERTIFICATE_BYTES, "equity source")
                .map_err(|e| invalid(e.to_string()))?,
        )?;
        let roles = |r: &mut Reader<'_>| -> Result<Vec<VId>, Refusal> {
            let count = r
                .count(MAX_SCOPE, "equity role accounts")
                .map_err(|e| invalid(e.to_string()))?;
            if count > r.remaining() / 16 {
                return Err(invalid("truncated equity role accounts"));
            }
            (0..count)
                .map(|_| {
                    r.u128("equity role account")
                        .map(VId)
                        .map_err(|e| invalid(e.to_string()))
                })
                .collect()
        };
        let issuance_accounts = roles(&mut r)?;
        let distribution_accounts = roles(&mut r)?;
        let output = r
            .bytes(MAX_EQUITY_CERTIFICATE_BYTES, "equity output")
            .map_err(|e| invalid(e.to_string()))?
            .to_vec();
        let digest = r
            .fixed::<32>("equity digest")
            .map_err(|e| invalid(e.to_string()))?;
        r.finish().map_err(|e| invalid(e.to_string()))?;
        let scope = source.request();
        let request = EquityRollForwardRequest {
            units: scope.units.clone(),
            label: scope.label.clone(),
            effective_from: scope.effective_from,
            effective_through: scope.effective_through,
            known_at: scope.known_at,
            issuance_accounts,
            distribution_accounts,
        };
        let certificate = Self {
            legacy,
            source,
            request,
            output,
            digest,
        };
        if certificate.canonical_bytes()? != bytes {
            return Err(invalid("noncanonical equity certificate"));
        }
        Ok(certificate)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body_bytes()?;
        if domain_digest(self.digest_domain(), &[&bytes]) != self.digest {
            return Err(invalid(
                "equity certificate digest differs from its contents",
            ));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Certify all equity/income leaves at one prefix, including zero leaves.
    /// Produce authority is required before selecting the chart or journal.
    pub fn certify_equity_roll_forward(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &EquityRollForwardRequest,
    ) -> Outcome<CertifiedEquityRollForward> {
        if let Err(denial) =
            fa_policy::require(capability, Op::Produce, "certifying an equity roll-forward")
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let scope = match self.equity_source_request(cx, principal, capability, request)? {
            Ok(scope) => scope,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let at = scope.known_at.ok_or_else(|| {
            BookError::Kernel(fa_journal::KernelError::Corrupt(
                "equity source has no fixed prefix".into(),
            ))
        })?;
        let request = match normalize(request, at) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let certified = match self.certify_roll_forward(cx, principal, capability, &scope)? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let citations = self.equity_adjustment_citations(cx, &certified.report)?;
        let report = match crate::roll_forward::equity_from_lead_schedule(
            certified.report,
            &request,
            &citations,
            false,
        ) {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let certificate =
            match EquityRollForwardCertificate::seal(certified.certificate, request, &report) {
                Ok(certificate) => certificate,
                Err(refusal) => return Ok(Err(refusal)),
            };
        Ok(Ok(CertifiedEquityRollForward {
            report,
            certificate,
        }))
    }

    /// Replay against a recipient's independently retained request. Reconstruct
    /// the full historical chart scope before accepting the source schedule;
    /// a valid schedule missing an equity leaf cannot certify this statement.
    pub fn replay_equity_roll_forward(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &EquityRollForwardCertificate,
        expected: &EquityRollForwardRequest,
    ) -> Outcome<EquityRollForwardReport> {
        let scope = match self.equity_source_request(cx, principal, capability, expected)? {
            Ok(scope) => scope,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(at) = expected.known_at else {
            return Ok(Err(invalid(
                "equity replay requires an independently selected fixed prefix",
            )));
        };
        let expected = match normalize(expected, at) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if expected != certificate.request {
            return Ok(Err(invalid(
                "delivered equity certificate differs from the expected scope or classification",
            )));
        }
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        let source = match self.replay_roll_forward_for(
            cx,
            principal,
            capability,
            &certificate.source,
            &scope,
        )? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let citations = if certificate.legacy {
            Default::default()
        } else {
            self.equity_adjustment_citations(cx, &source)?
        };
        let report = match crate::roll_forward::equity_from_lead_schedule(
            source,
            &expected,
            &citations,
            certificate.legacy,
        ) {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let output = match report.canonical_bytes_for(certificate.legacy) {
            Ok(output) => output,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "equity amounts, account metadata or movement citations did not replay",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}
