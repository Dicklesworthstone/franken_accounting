//! A scenario diff as a retained, replayable certificate (plan §15.2,
//! §15.6.5; bead fa-k07b).
//!
//! The certificate binds both sides of the comparison. Trunk: a complete
//! native trial-balance certificate at the scenario's fork sequence over the
//! diff's periods (stock balances or period activity), replayed exactly as a
//! `fa tb --certify` certificate is. Scenario: its vertex, body digest, the
//! Plan records the diff covers (a prefix of the scenario's intents, in
//! planning order), the replay's `SeqMap` digest and the materialization's
//! head. Replay re-materializes the scenario from trunk with exactly those
//! intents, under every posting law, re-diffs it and compares the canonical
//! output byte for byte, so an intent run in the scenario later never changes
//! what an earlier certificate replays.
//!
//! Version 2 fixes the replay law to the protected native coordinates used
//! by bank closes. Version 1 was emitted with both compressed and protected
//! coordinates: replay first tries the protected form, then the historical
//! compressed form only after a successful replay differs from the bound
//! output. Both validate the original source and enforce every posting law.
//! An integrity or posting refusal never selects the legacy form.
//!
//! No-claim boundary: the scenario side is not a native certificate (a
//! scratch book cannot carry trunk certificate identities); its evidence is
//! the re-performed materialization. Producer and capability commitment are
//! unsigned provenance, never authority to read a book.

use std::collections::BTreeSet;

use fa_journal::{Refusal, exit};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op, Reach};
use fgdb_types::{CommitSeq, VId};

use super::{ScenarioDiff, ScenarioReplay};
use crate::{
    Book, CertificateStatus, Outcome, ReportCertificate, ReportOutput, ReportSelection,
    RetainedCertificate, TrialBalanceSelection,
};

/// The family's format field (`ReportArtifact::decode` dispatches on it).
pub const CERTIFICATE_FORMAT: &[u8] = b"fa:scenario-diff-certificate:v2";
/// Original certificates retain their exact bytes and historical replay law.
pub const LEGACY_CERTIFICATE_FORMAT: &[u8] = b"fa:scenario-diff-certificate:v1";
/// The canonical output's format (`report_certificate.output_format`).
pub const OUTPUT_FORMAT: &str = "fa:scenario-diff:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:scenario-diff-certificate-digest:v2";
const LEGACY_DIGEST_DOMAIN: &[u8] = b"fa:scenario-diff-certificate-digest:v1";
const MAX_BYTES: usize = crate::certificate::MAX_CERTIFICATE_BYTES;
const MAX_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    LegacyV1,
    ProtectedV2,
}

impl Version {
    const fn format(self) -> &'static [u8] {
        match self {
            Self::LegacyV1 => LEGACY_CERTIFICATE_FORMAT,
            Self::ProtectedV2 => CERTIFICATE_FORMAT,
        }
    }

    const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::LegacyV1 => LEGACY_DIGEST_DOMAIN,
            Self::ProtectedV2 => DIGEST_DOMAIN,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioDiffCertificate {
    version: Version,
    trunk: ReportCertificate,
    scenario: VId,
    name: String,
    body_digest: [u8; 32],
    intents: Vec<VId>,
    seq_map_digest: [u8; 32],
    scenario_known_at: CommitSeq,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

/// A scenario diff and the certificate that replays it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedScenarioDiff {
    pub report: ScenarioDiff,
    pub certificate: ScenarioDiffCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §15.2, §15.6.5 (a scenario diff replays from its trunk certificate and its pinned intents)",
        "replay the complete certificate in its original book with fa replay; a scenario diff is never edited, only certified again",
    )
}

fn malformed(error: DecodeError) -> Refusal {
    invalid(format!("malformed scenario diff certificate: {error}"))
}

/// The diff's exact canonical output: every field a reader sees, in order.
pub(crate) fn output_bytes(diff: &ScenarioDiff) -> Result<Vec<u8>, Refusal> {
    let mut w = Writer::new();
    w.str(OUTPUT_FORMAT)
        .str(&diff.name)
        .u128(diff.scenario.0)
        .fixed(&diff.body_digest)
        .fixed(&diff.intents_digest)
        .u64(diff.intents as u64)
        .u64(diff.fork_at.0)
        .opt(diff.from.as_ref(), |w, d| {
            w.i32(d.0);
        })
        .list(&diff.assumptions, |w, oid| {
            w.fixed(&oid.0);
        })
        .list(&diff.periods, |w, period| {
            w.str(period);
        })
        .bool(diff.activity)
        .fixed(&diff.seq_map_digest)
        .u64(diff.scenario_known_at.0)
        .list(&diff.rows, |w, row| {
            w.u128(row.account.0)
                .str(&row.code)
                .str(&row.name)
                .u32(row.unit_id)
                .i128(row.trunk_debits)
                .i128(row.trunk_credits)
                .i128(row.scenario_debits)
                .i128(row.scenario_credits)
                .i128(row.delta)
                .i128(row.trunk_debits_pending)
                .i128(row.trunk_credits_pending)
                .i128(row.scenario_debits_pending)
                .i128(row.scenario_credits_pending)
                .i128(row.pending_delta);
        });
    w.finish().map_err(|e| invalid(e.to_string()))
}

/// The trunk side's selection: stock balances or activity over periods.
fn trunk_periods(trunk: &ReportCertificate) -> Result<(Vec<String>, bool), Refusal> {
    match &trunk.selection {
        ReportSelection::TrialBalance(TrialBalanceSelection::Periods(periods)) => {
            Ok((periods.clone(), false))
        }
        ReportSelection::TrialBalance(TrialBalanceSelection::Activity(periods)) => {
            Ok((periods.clone(), true))
        }
        _ => Err(invalid(
            "a scenario diff's trunk source is a trial balance over periods",
        )),
    }
}

impl ScenarioDiffCertificate {
    #[allow(clippy::too_many_arguments)]
    fn seal(
        trunk: ReportCertificate,
        scenario: VId,
        name: String,
        body_digest: [u8; 32],
        intents: Vec<VId>,
        seq_map_digest: [u8; 32],
        scenario_known_at: CommitSeq,
        producer: VId,
        capability_commitment: [u8; 32],
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            version: Version::ProtectedV2,
            trunk,
            scenario,
            name,
            body_digest,
            intents,
            seq_map_digest,
            scenario_known_at,
            producer,
            capability_commitment,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(value.version.digest_domain(), &[&value.body()?]);
        value.validate()?;
        Ok(value)
    }

    fn body(&self) -> Result<Vec<u8>, Refusal> {
        let trunk = self
            .trunk
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        let mut w = Writer::new();
        w.bytes(self.version.format())
            .bytes(&trunk)
            .u128(self.scenario.0)
            .str(&self.name)
            .fixed(&self.body_digest)
            .list(&self.intents, |w, record| {
                w.u128(record.0);
            })
            .fixed(&self.seq_map_digest)
            .u64(self.scenario_known_at.0)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn validate(&self) -> Result<(), Refusal> {
        if self.trunk.branch_id != Id128::TRUNK || self.trunk.time_selection.is_some() {
            return Err(invalid(
                "a scenario diff's trunk source is a sequence-selected trunk certificate",
            ));
        }
        trunk_periods(&self.trunk)?;
        if self.name.is_empty() || self.name.len() > MAX_NAME_BYTES {
            return Err(invalid("a scenario diff names its scenario"));
        }
        if self.intents.len() > fa_model::limits::MAX_BATCH_ENTRIES
            || self.intents.iter().collect::<BTreeSet<_>>().len() != self.intents.len()
        {
            return Err(invalid(
                "a scenario diff's intents are distinct Plan records within the scenario cap",
            ));
        }
        if self.scenario_known_at.0 == 0 {
            return Err(invalid("a scenario diff names its materialization's head"));
        }
        if domain_digest(self.version.digest_domain(), &[&self.body()?]) != self.digest {
            return Err(invalid("scenario diff certificate digest mismatch"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body()?;
        bytes.extend_from_slice(&self.digest);
        if bytes.len() > MAX_BYTES {
            return Err(invalid(
                "scenario diff certificate exceeds the 64 MiB format bound",
            ));
        }
        Ok(bytes)
    }

    /// Decode and validate the bounded container and its trunk source. This
    /// is not the historical claim: only [`Book::replay_scenario_diff`]
    /// establishes that.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_BYTES {
            return Err(invalid(
                "scenario diff certificate exceeds the 64 MiB format bound",
            ));
        }
        let mut r = Reader::new(bytes);
        let version = match r.bytes(64, "format").map_err(malformed)? {
            CERTIFICATE_FORMAT => Version::ProtectedV2,
            LEGACY_CERTIFICATE_FORMAT => Version::LegacyV1,
            _ => {
                return Err(invalid(
                    "not a scenario diff certificate of a supported version",
                ));
            }
        };
        let trunk =
            ReportCertificate::decode(r.bytes(MAX_BYTES, "trunk source").map_err(malformed)?)?;
        let scenario = VId(r.u128("scenario").map_err(malformed)?);
        let name = r
            .str(MAX_NAME_BYTES, "scenario name")
            .map_err(malformed)?
            .to_string();
        let body_digest = r.fixed::<32>("body digest").map_err(malformed)?;
        let intents = r
            .list(fa_model::limits::MAX_BATCH_ENTRIES, "intents", |r| {
                Ok(VId(r.u128("intent record")?))
            })
            .map_err(malformed)?;
        let seq_map_digest = r.fixed::<32>("seq map digest").map_err(malformed)?;
        let scenario_known_at = CommitSeq(r.u64("scenario known-at").map_err(malformed)?);
        let producer = VId(r.u128("producer").map_err(malformed)?);
        let capability_commitment = r.fixed::<32>("capability commitment").map_err(malformed)?;
        let output = r.bytes(MAX_BYTES, "output").map_err(malformed)?.to_vec();
        let digest = r.fixed::<32>("digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            version,
            trunk,
            scenario,
            name,
            body_digest,
            intents,
            seq_map_digest,
            scenario_known_at,
            producer,
            capability_commitment,
            output,
            digest,
        };
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical scenario diff certificate"));
        }
        Ok(value)
    }

    #[must_use]
    pub fn format(&self) -> &'static [u8] {
        self.version.format()
    }

    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// The trunk side: a native trial-balance certificate at the fork.
    #[must_use]
    pub fn trunk(&self) -> &ReportCertificate {
        &self.trunk
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The Plan records the diff covers, in planning order.
    #[must_use]
    pub fn intents(&self) -> &[VId] {
        &self.intents
    }
}

/// Current authority before any read: read (and produce, to certify or
/// retain), the whole book in reach.
fn authorize(book: &Book, principal: VId, capability: &Capability, produce: bool) -> Outcome<()> {
    if let Err(refusal) = book.read_scope(principal, capability)? {
        return Ok(Err(refusal));
    }
    let admitted = fa_policy::reach(capability, &Reach::whole_book(true), None).and_then(|()| {
        if produce {
            fa_policy::require(capability, Op::Produce, "certifying a scenario diff")
        } else {
            Ok(())
        }
    });
    Ok(admitted.map_err(|denial| fa_journal::policy::refusal(&denial)))
}

impl Book {
    /// The diff of the scenario `name` over `periods` with a certificate that
    /// replays it: the trunk side certified natively at the fork, the
    /// scenario side bound to its body and to exactly the intents it holds
    /// now. Certifying writes nothing; [`Book::retain_scenario_diff`] keeps
    /// the certificate in the book.
    pub fn certify_scenario_diff(
        &mut self,
        principal: VId,
        capability: &Capability,
        name: &str,
        periods: &[String],
        activity: bool,
    ) -> Outcome<CertifiedScenarioDiff> {
        if let Err(refusal) = authorize(self, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        let Some(view) = self.scenario(name)? else {
            return Ok(Err(super::unknown(name)));
        };
        let mut periods = periods.to_vec();
        periods.sort();
        periods.dedup();
        let selection = if activity {
            TrialBalanceSelection::Activity(periods.clone())
        } else {
            TrialBalanceSelection::Periods(periods.clone())
        };
        let certified = match self.certify_report(
            ReportSelection::TrialBalance(selection),
            Some(view.body.fork_at),
        )? {
            Ok(certified) => certified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let ReportOutput::TrialBalance(trunk) = certified.report else {
            return Ok(Err(invalid(
                "the trunk source did not certify a trial balance",
            )));
        };
        let scenario = view.vid;
        let scenario_name = view.body.name.clone();
        let body_digest = view.body.digest()?;
        let intents: Vec<VId> = view.intents.iter().map(|planned| planned.record).collect();
        let through = intents.len();
        let report = match self.diff_view(view, through, &trunk, &periods, activity)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let commitment = capability.commitment().map_err(|e| invalid(e.to_string()));
        let certificate = commitment.and_then(|commitment| {
            ScenarioDiffCertificate::seal(
                certified.certificate,
                scenario,
                scenario_name,
                body_digest,
                intents,
                report.seq_map_digest,
                report.scenario_known_at,
                principal,
                commitment,
                output_bytes(&report)?,
            )
        });
        Ok(certificate.map(|certificate| CertifiedScenarioDiff {
            report,
            certificate,
        }))
    }

    /// Replay a scenario diff certificate under current authority: replay its
    /// trunk certificate, re-materialize the scenario with exactly its
    /// recorded intents (the scenario may hold later ones), re-diff and
    /// compare the canonical output. Certificate provenance grants nothing.
    pub fn replay_scenario_diff(
        &mut self,
        principal: VId,
        capability: &Capability,
        certificate: &ScenarioDiffCertificate,
    ) -> Outcome<ScenarioDiff> {
        if let Err(refusal) = authorize(self, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        if certificate.trunk.book_id != self.context().book_id {
            return Ok(Err(invalid("the scenario diff belongs to another book")));
        }
        if let Err(refusal) = certificate.validate() {
            return Ok(Err(refusal));
        }
        let (periods, activity) = match trunk_periods(&certificate.trunk) {
            Ok(selection) => selection,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let trunk = match self.replay_report(&certificate.trunk)? {
            Ok(ReportOutput::TrialBalance(trunk)) => trunk,
            Ok(_) => {
                return Ok(Err(invalid(
                    "the trunk source replayed but is not a trial balance",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(view) = self.scenario(&certificate.name)? else {
            return Ok(Err(invalid(format!(
                "this book has no scenario `{}`",
                certificate.name
            ))));
        };
        let recorded: Vec<VId> = view.intents.iter().map(|planned| planned.record).collect();
        if view.vid != certificate.scenario
            || view.body.digest()? != certificate.body_digest
            || view.body.fork_at != certificate.trunk.known_at
            || !recorded.starts_with(&certificate.intents)
        {
            return Ok(Err(invalid(
                "the book's scenario is not the one the diff certified (its body, fork or intents differ)",
            )));
        }
        let through = certificate.intents.len();
        let report = match self.diff_view(view.clone(), through, &trunk, &periods, activity)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let matches = |report: &ScenarioDiff| -> Result<bool, Refusal> {
            Ok(report.seq_map_digest == certificate.seq_map_digest
                && report.scenario_known_at == certificate.scenario_known_at
                && output_bytes(report)? == certificate.output)
        };
        match matches(&report) {
            Ok(true) => return Ok(Ok(report)),
            Ok(false) => {}
            Err(refusal) => return Ok(Err(refusal)),
        }
        if certificate.version == Version::LegacyV1 {
            // The v1 format predates the protected replay law and was also
            // emitted during its rollout. Only a successful, source-verified
            // current replay whose exact bound output differs may reach this
            // second reconstruction. Refusals above are never bypassed.
            let legacy = match self.diff_view_with_replay(
                view,
                through,
                &trunk,
                &periods,
                activity,
                ScenarioReplay::LegacyCertificateV1,
            )? {
                Ok(report) => report,
                Err(refusal) => return Ok(Err(refusal)),
            };
            match matches(&legacy) {
                Ok(true) => return Ok(Ok(legacy)),
                Ok(false) => {}
                Err(refusal) => return Ok(Err(refusal)),
            }
        }
        Ok(Err(invalid(
            "the scenario re-materialized at a different replay or output than the one certified",
        )))
    }

    /// Whether certifying the scenario now would reproduce this
    /// certificate, after the whole certificate replays under current
    /// authority. Its trunk side is fixed at the fork, so later trunk
    /// entries never supersede it; a Plan record the scenario gained after
    /// the certified prefix does, and `later_entries` names those records
    /// in planning order. A discarded scenario gains none.
    pub fn scenario_diff_status(
        &mut self,
        principal: VId,
        capability: &Capability,
        certificate: &ScenarioDiffCertificate,
    ) -> Outcome<CertificateStatus> {
        if let Err(refusal) = self.replay_scenario_diff(principal, capability, certificate)? {
            return Ok(Err(refusal));
        }
        let checked_at = self.head()?;
        let Some(view) = self.scenario(&certificate.name)? else {
            return Ok(Err(invalid(format!(
                "this book has no scenario `{}`",
                certificate.name
            ))));
        };
        let later_entries: Vec<VId> = view
            .intents
            .iter()
            .skip(certificate.intents.len())
            .map(|planned| planned.record)
            .collect();
        Ok(Ok(if later_entries.is_empty() {
            CertificateStatus::Current { checked_at }
        } else {
            CertificateStatus::SupersededBy {
                checked_at,
                later_entries,
            }
        }))
    }

    /// Replay a scenario diff certificate in full, then keep it in the book
    /// under its own digest (read and produce authority, current). An exact
    /// retry publishes nothing and returns the original sequence.
    pub fn retain_scenario_diff(
        &mut self,
        principal: VId,
        capability: &Capability,
        certificate: &ScenarioDiffCertificate,
    ) -> Outcome<RetainedCertificate> {
        if let Err(refusal) = authorize(self, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        // The replay reads trunk and builds a separate scratch book; it
        // writes nothing here, so the head it verified is the one retention
        // binds (a later write refuses the retention as a conflict).
        let verified_at = self.head()?;
        if let Err(refusal) = self.replay_scenario_diff(principal, capability, certificate)? {
            return Ok(Err(refusal));
        }
        self.retain_replayed_scenario_diff(principal, capability, certificate, verified_at)
    }
}

#[cfg(test)]
#[path = "certificate/replay_tests.rs"]
mod replay_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_foreign_or_truncated_container_is_refused_before_any_replay() {
        assert!(ScenarioDiffCertificate::decode(b"").is_err());
        let mut w = Writer::new();
        w.bytes(b"fa:statement-diff-certificate:v1");
        let other = w.finish().unwrap();
        let refused = ScenarioDiffCertificate::decode(&other).unwrap_err();
        assert!(
            refused.message.contains("not a scenario diff"),
            "{refused:?}"
        );
        let mut w = Writer::new();
        w.bytes(CERTIFICATE_FORMAT)
            .bytes(b"not a report certificate");
        let truncated = w.finish().unwrap();
        assert!(ScenarioDiffCertificate::decode(&truncated).is_err());
    }
}
