//! One retained pair of whole-book sources for the complete chart partition.
//! Decoding is content integrity only. Current authority, both native replays,
//! historical chart reconstruction and the recipient's exact question are
//! mandatory before accepting any amount or coverage claim. These unsigned
//! artifacts contain whole-book financial inputs even for a selected subset.

use super::*;
use crate::aging::{AgingCertificate, AgingRequest};
use crate::{ReportCertificate, ReportOutput, ReportSelection, TrialBalanceSelection};
use fa_model::{DecodeError, Reader, domain_digest};

mod workpaper;

pub(crate) const FORMAT: &[u8] = b"fa:aging-portfolio-certificate:v1";
const DIGEST: &[u8] = b"fa:aging-portfolio-digest:v1";

#[derive(Clone, PartialEq, Eq)]
pub struct AgingPortfolioCertificate {
    aging: AgingCertificate,
    control: ReportCertificate,
    scope: AgingAccountScope,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

impl core::fmt::Debug for AgingPortfolioCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgingPortfolioCertificate")
            .field("digest", &self.digest)
            .field("output_len", &self.output.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedAgingPortfolio {
    pub report: AgingPortfolio,
    pub certificate: AgingPortfolioCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §5.6–§5.7 / §7.5 / §13.6 (complete chart partition and original native prefixes)",
        "retain both original whole-book sources and history; independently select the scope, civil cutoff, fixed recorded sequence and aging bounds",
    )
}

fn bounded(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    super::bounded(parts).map_err(|r| invalid(r.message))
}

fn question(
    aging: &AgingCertificate,
    control: &ReportCertificate,
    scope: &AgingAccountScope,
) -> Result<AgingPortfolioRequest, Refusal> {
    let request = aging.request()?;
    let source = aging.source();
    if request.account.is_some()
        || source.book_id != control.book_id
        || source.branch_id != Id128::TRUNK
        || control.branch_id != Id128::TRUNK
        || source.time_selection.is_some()
        || control.time_selection.is_some()
        || source.known_at != control.known_at
        || source.journal_root != control.journal_root
        || source.journal_leaves != control.journal_leaves
        || control.selection
            != ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(request.effective_through))
    {
        return Err(invalid(
            "portfolio requires whole-book aging and stock sources at the same book, prefix and cutoff",
        ));
    }
    let actual = AgingPortfolioRequest {
        scope: scope.clone(),
        effective_through: request.effective_through,
        known_at: Some(source.known_at),
        buckets: request.buckets,
    };
    if normalize(&actual, source.known_at).map_err(|e| invalid(e.message))? != actual {
        return Err(invalid(
            "portfolio certificate account scope is not canonical",
        ));
    }
    Ok(actual)
}

fn expect(expected: &AgingPortfolioRequest, actual: &AgingPortfolioRequest) -> Result<(), Refusal> {
    let at = expected.known_at.ok_or_else(|| {
        selection_error("recipient portfolio expectations must fix known-at, not HEAD")
    })?;
    // Scope order has no meaning, but duplicates remain errors. AllPosting and
    // a hand-picked list remain different questions even if coverage is equal.
    let expected = normalize(expected, at)?;
    if &expected != actual {
        return Err(invalid(
            "portfolio certificate answers a different recipient-selected question",
        ));
    }
    Ok(())
}

impl AgingPortfolioCertificate {
    #[must_use]
    pub fn aging_source(&self) -> &AgingCertificate {
        &self.aging
    }
    #[must_use]
    pub fn control_source(&self) -> &ReportCertificate {
        &self.control
    }
    #[must_use]
    pub fn producer(&self) -> VId {
        self.producer
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn request(&self) -> Result<AgingPortfolioRequest, Refusal> {
        question(&self.aging, &self.control, &self.scope)
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        self.request()?;
        bounded([self.output.len()])?;
        let aging = self.aging.canonical_bytes()?;
        let control = self
            .control
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        ReportCertificate::decode(&control)?; // its public fields are not prevalidated
        let scope_size = match &self.scope {
            AgingAccountScope::AllPosting => 1,
            AgingAccountScope::Selected(ids) => 5 + ids.len() * 16,
        };
        let size = bounded([
            4,
            FORMAT.len(),
            16,
            32,
            scope_size,
            4,
            aging.len(),
            4,
            control.len(),
            4,
            self.output.len(),
            32,
        ])?;
        let mut w = Writer::with_capacity(size);
        w.bytes(FORMAT)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment);
        write_scope(&mut w, &self.scope);
        w.bytes(&aging).bytes(&control).bytes(&self.output);
        let body = w.finish().map_err(|e| invalid(e.to_string()))?;
        if body.len().checked_add(32) != Some(size) {
            return Err(invalid("portfolio certificate length mismatch"));
        }
        Ok(body)
    }

    fn seal(
        aging: AgingCertificate,
        control: ReportCertificate,
        scope: AgingAccountScope,
        producer: VId,
        capability_commitment: [u8; 32],
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            aging,
            control,
            scope,
            producer,
            capability_commitment,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Canonical bounded unsigned container, NOT historical verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST, &[&body]) != self.digest {
            return Err(invalid("portfolio certificate digest mismatch"));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        bounded([bytes.len()])?;
        let malformed = |e: DecodeError| invalid(format!("malformed portfolio certificate: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "portfolio format").map_err(malformed)? != FORMAT {
            return Err(invalid("unsupported portfolio certificate format"));
        }
        let producer = VId(r.u128("portfolio producer").map_err(malformed)?);
        let capability_commitment = r.fixed::<32>("portfolio capability").map_err(malformed)?;
        let scope = match r.u8("portfolio scope").map_err(malformed)? {
            0 => AgingAccountScope::AllPosting,
            1 => {
                let count = r
                    .count(MAX_AGING_PORTFOLIO_ACCOUNTS, "portfolio accounts")
                    .map_err(malformed)?;
                let mut ids = Vec::with_capacity(count);
                for _ in 0..count {
                    ids.push(VId(r.u128("portfolio account").map_err(malformed)?));
                }
                if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(invalid("noncanonical portfolio account list"));
                }
                AgingAccountScope::Selected(ids)
            }
            _ => return Err(invalid("unknown portfolio scope tag")),
        };
        let aging = AgingCertificate::decode(
            r.bytes(MAX_AGING_PORTFOLIO_BYTES, "portfolio aging source")
                .map_err(malformed)?,
        )?;
        let control = ReportCertificate::decode(
            r.bytes(MAX_AGING_PORTFOLIO_BYTES, "portfolio control source")
                .map_err(malformed)?,
        )?;
        let output = r
            .bytes(MAX_AGING_PORTFOLIO_BYTES, "portfolio comparison")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed::<32>("portfolio digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            aging,
            control,
            scope,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical portfolio certificate"));
        }
        Ok(value)
    }
}

fn package(
    report: AgingPortfolio,
    aging: AgingCertificate,
    control: ReportCertificate,
    principal: VId,
    capability: &Capability,
) -> Result<CertifiedAgingPortfolio, Refusal> {
    if report.book_id() != aging.source().book_id {
        return Err(invalid("portfolio result and sources name different books"));
    }
    let actual = question(&aging, &control, &report.request.scope)?;
    expect(report.request(), &actual)?;
    let output = report.canonical_bytes()?;
    let commitment = capability
        .commitment()
        .map_err(|e| invalid(e.to_string()))?;
    let certificate = AgingPortfolioCertificate::seal(
        aging,
        control,
        report.request.scope.clone(),
        principal,
        commitment,
        output,
    )?;
    Ok(CertifiedAgingPortfolio {
        report,
        certificate,
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Produce one shared source pair, rather than N duplicated certificates.
    /// Neither these sources nor the portfolio are appended to the journal.
    pub fn certify_aging_portfolio(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AgingPortfolioRequest,
    ) -> Outcome<CertifiedAgingPortfolio> {
        let head = match authorize(self, cx, principal, capability, true)? {
            Ok(h) => h,
            Err(r) => return Ok(Err(r)),
        };
        let request = match normalize(request, head) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let at = request.known_at.unwrap_or(head);
        let query = cx.query();
        let chart = query.with_restriction(|| {
            crate::certificate::context_at(&self.db, self.context(), at)?;
            fa_journal::chart::read_at(&self.db, self.context(), at).map_err(BookError::from)
        })?;
        let chosen = match selected(&chart, &request.scope) {
            Ok(ids) => ids,
            Err(r) => return Ok(Err(r)),
        };
        query.checkpoint().map_err(BookError::Context)?;
        let aging = match self.certify_effective_date_aging(
            cx,
            principal,
            capability,
            &AgingRequest {
                account: None,
                effective_through: request.effective_through,
                known_at: Some(at),
                buckets: request.buckets.clone(),
            },
        )? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let control = match query.with_restriction(|| {
            crate::certificate::certify_report(
                &self.db,
                cx,
                self.context(),
                TrialBalanceSelection::AsOf(request.effective_through).into(),
                Some(at),
            )
        })? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let ReportOutput::TrialBalance(balance) = control.report else {
            return Ok(Err(invalid(
                "portfolio control source is not a trial balance",
            )));
        };
        let report = match partition(
            self.context().book_id,
            request,
            chart.accounts(),
            &chosen,
            aging.report,
            balance,
            &self.context().units,
        )? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let result = package(
            report,
            aging.certificate,
            control.certificate,
            principal,
            capability,
        );
        query.checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    /// Replay and reuse the original whole-book sources byte-for-byte. Scope
    /// is chosen independently; equal totals never permit a different prefix.
    pub fn certify_aging_portfolio_from_sources(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        aging: &AgingCertificate,
        control: &ReportCertificate,
        expected: &AgingPortfolioRequest,
    ) -> Outcome<CertifiedAgingPortfolio> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        let at = match expected.known_at {
            Some(at) => at,
            None => {
                return Ok(Err(selection_error(
                    "saved portfolio sources require a fixed recipient prefix",
                )));
            }
        };
        let expected = match normalize(expected, at) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let report = match self
            .replay_portfolio_sources(cx, principal, capability, aging, control, &expected)?
        {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let result = package(
            report,
            aging.clone(),
            control.clone(),
            principal,
            capability,
        );
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    fn replay_portfolio_sources(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        aging: &AgingCertificate,
        control: &ReportCertificate,
        expected: &AgingPortfolioRequest,
    ) -> Outcome<AgingPortfolio> {
        let actual = match question(aging, control, &expected.scope) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        if let Err(r) = expect(expected, &actual) {
            return Ok(Err(r));
        }
        let aged = match self.replay_effective_date_aging(cx, principal, capability, aging)? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let balance = match self.replay_report(cx, control)? {
            Ok(ReportOutput::TrialBalance(report)) => report,
            Ok(_) => {
                return Ok(Err(invalid(
                    "replayed portfolio control source is not a trial balance",
                )));
            }
            Err(r) => return Ok(Err(r)),
        };
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        // Both source replays authenticate the native Account closure and the
        // complete immutable journal prefix used by this install-only chart.
        let chart = query.with_restriction(|| {
            fa_journal::chart::read_at(&self.db, self.context(), aged.known_at)
        })?;
        let chosen = match selected(&chart, &actual.scope) {
            Ok(ids) => ids,
            Err(r) => return Ok(Err(r)),
        };
        let result = partition(
            self.context().book_id,
            actual,
            chart.accounts(),
            &chosen,
            aged,
            balance,
            &self.context().units,
        )?;
        query.checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    /// A repaired checksum cannot conceal dropped coverage, a false comparison
    /// or a substituted question. Recompute all accounts and compare every byte.
    pub fn replay_aging_portfolio(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AgingPortfolioCertificate,
        expected: &AgingPortfolioRequest,
    ) -> Outcome<AgingPortfolio> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        if let Err(r) = certificate.canonical_bytes() {
            return Ok(Err(r));
        }
        let actual = match certificate.request() {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        if let Err(r) = expect(expected, &actual) {
            return Ok(Err(r));
        }
        let report = match self.replay_portfolio_sources(
            cx,
            principal,
            capability,
            &certificate.aging,
            &certificate.control,
            &actual,
        )? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let output = match report.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(r) => return Ok(Err(r)),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "replayed portfolio amounts or coverage differ from saved output",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}

#[cfg(test)]
mod tests;
