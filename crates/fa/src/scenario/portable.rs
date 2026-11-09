//! A deliberately narrower outsider claim than native scenario replay. The
//! producer reruns the ordinary native replay, while the portable interpreter
//! independently checks only additive Original mathematics and its exact
//! assumptions. Historical authority and native marker membership are unjudged.

use std::collections::BTreeSet;

use fa_journal::{DocumentRead, Refusal, exit};
use fa_model::{EntryClass, EntryOrigin, Oid};
use fa_notary::scenario::{
    MAX_SCENARIO_DOCUMENTS, MAX_SCENARIO_MATH_BYTES, ScenarioDocument, assemble,
};
use fa_policy::Capability;
use fgdb_types::{CommitSeq, VId};

use super::{SCENARIO_DIFF_CERTIFICATE_FORMAT, ScenarioDiffCertificate, certificate};
use crate::{Book, BookError, Outcome, ProducedBundle};

/// Export the recipient's question alongside a native diff, before delivery of
/// its proof. This is not a claim that the selected intents fit the portable
/// profile; production and verification separately enforce that profile.
pub fn scenario_math_request(
    book_id: fa_model::Id128,
    diff: &super::ScenarioDiff,
) -> Result<Vec<u8>, Refusal> {
    if diff.name.is_empty()
        || diff.name.len() > 128
        || diff.fork_at.0 == 0
        || diff.periods.is_empty()
        || diff.periods.len() > 4096
        || diff.periods.iter().any(|p| p.is_empty() || p.len() > 128)
        || diff.periods.windows(2).any(|p| p[0] >= p[1])
        || diff.assumptions.len() > 256
        || diff.assumptions.windows(2).any(|p| p[0] >= p[1])
        || diff.intents > fa_model::limits::MAX_BATCH_ENTRIES
    {
        return Err(refused(
            "scenario request must name canonical, bounded periods and assumptions",
        ));
    }
    let mut w = fa_model::Writer::new();
    w.bytes(b"fa:scenario-math-request:v1")
        .str(super::NATIVE_ORIGINAL_ADDITIVE_METHOD)
        .fixed(&book_id.0)
        .str(&diff.name)
        .u64(diff.fork_at.0)
        .opt(diff.from.as_ref(), |w, day| {
            w.i32(day.0);
        })
        .list(&diff.periods, |w, period| {
            w.str(period);
        })
        .bool(diff.activity)
        .list(&diff.assumptions, |w, oid| {
            w.fixed(&oid.0);
        })
        .u64(diff.intents as u64)
        .fixed(&diff.intents_digest);
    w.finish().map_err(|error| refused(error.to_string()))
}

pub(crate) fn refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_notary::code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §13.3 / §15.2 (conditional additive scenario mathematics)",
        "use a v2 scenario certificate with native, dimensionless Original PostEntry assumptions; retain complete evidence and a checkpoint covering its Open and selected Plans; use native replay for other scenarios",
    )
}

/// Only this module can construct a value eligible for the private receipt
/// bridge, after native replay and full current-authority disclosure succeed.
pub(crate) struct PreparedScenarioMath {
    produced: ProducedBundle,
}

impl PreparedScenarioMath {
    pub(crate) fn sign(
        mut self,
        principal: VId,
        at: CommitSeq,
        commitment: [u8; 32],
        signer: &fa_notary::SigningKey,
    ) -> Result<ProducedBundle, BookError> {
        self.produced.receipt = fa_notary::ProductionReceipt::sign(
            fa_notary::ReceiptBody {
                bundle_digest: self.produced.bundle.digest,
                producer_principal: principal,
                produced_at_seq: at,
                capability_commitment: commitment,
                time_evidence_oid: self.produced.checkpoint.checkpoint.body.time_evidence_oid,
            },
            signer,
        )
        .map_err(|error| fa_journal::KernelError::Corrupt(error.to_string()))?
        .canonical_bytes()
        .map_err(|error| fa_journal::KernelError::Model(error.into()))?;
        Ok(self.produced)
    }
}

impl Book {
    /// Export conditional additive scenario mathematics for an outsider.
    ///
    /// The original certificate is replayed under every native posting law.
    /// Offline verification independently proves the complete trunk fold,
    /// exact journaled Open/Plan prefix, document commitments and resulting
    /// native per-unit gross differences. Hypothetical entries are assumed
    /// effects, never trunk members. Historical planner admission and native
    /// SeqMap marker membership remain explicitly unjudged.
    ///
    /// The bounded profile accepts only dimensionless native Original entries
    /// without approvals, controls, pending state, settlements, extensions or
    /// base valuation. A checkpoint must cover the Open and selected Plans,
    /// even for an empty diff. Returns None only for an unavailable checkpoint.
    pub fn produce_scenario_math_bundle(
        &mut self,
        principal: VId,
        capability: &Capability,
        state: Option<Oid>,
        source: &ScenarioDiffCertificate,
    ) -> Outcome<Option<ProducedBundle>> {
        if let Err(refusal) = certificate::authorize(self, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        if source.format() != SCENARIO_DIFF_CERTIFICATE_FORMAT {
            return Ok(Err(refused(
                "portable scenario mathematics requires the native v2 replay law",
            )));
        }
        let Some(view) = self.scenario(source.name())? else {
            return Ok(Err(refused("the source scenario is absent")));
        };
        let through = source.intents().len();
        if view.intents.len() < through {
            return Ok(Err(refused("selected scenario Plan prefix is unavailable")));
        }
        let mut document_oids: BTreeSet<Oid> = view.assumptions.iter().copied().collect();
        for planned in view.intents.iter().take(through) {
            let p = planned.intent.proposal();
            if p.class != EntryClass::ORIGINAL
                || p.schema_minor > 1
                || !matches!(p.origin, EntryOrigin::Intent { intent_kind: 1, .. })
                || !planned.intent.approvals().is_empty()
                || p.control.is_some()
                || p.base_totals.is_some()
                || p.pending.is_some()
                || !p.supersession.is_empty()
                || !p.extensions.is_empty()
                || p.legs.len() < 2
                || p.unit_totals
                    .iter()
                    .any(|total| total.debits != total.credits)
                || p.legs.iter().any(|leg| {
                    leg.base_amount.is_some()
                        || !leg.dimension_set.is_empty()
                        || !leg.settles.is_empty()
                })
            {
                return Ok(Err(refused(
                    "a selected Plan is outside native-original-additive:v1",
                )));
            }
            document_oids.extend(p.evidence.iter().map(|evidence| evidence.document_oid));
            if document_oids.len() > MAX_SCENARIO_DOCUMENTS {
                return Ok(Err(refused(
                    "scenario document closure exceeds its count bound",
                )));
            }
        }
        let report = match self.replay_scenario_diff(principal, capability, source)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // Materialize only the original fork here; the full native replay above
        // already checked the selected intents. This retains the actual map and
        // checks the additive profile's one-publication-per-new-intent premise.
        let fork = match self.materialize(view.clone(), 0)? {
            Ok(fork) => fork,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if fork.map.digest()? != report.seq_map_digest
            || fork.book.head()?.0.checked_add(through as u64) != Some(report.scenario_known_at.0)
        {
            return Ok(Err(refused(
                "scenario replay is not additive over distinct new publications",
            )));
        }
        let map = fork.map.canonical_bytes()?;
        let mut produced =
            match self.produce_report_bundle(principal, capability, state, source.trunk())? {
                Ok(Some(produced)) => produced,
                Ok(None) => return Ok(Ok(None)),
                Err(refusal) => return Ok(Err(refusal)),
            };
        let required = view
            .intents
            .iter()
            .take(through)
            .map(|plan| plan.recorded_at)
            .fold(view.opened_at, CommitSeq::max);
        if produced.checkpoint.checkpoint.body.statement.through_seq < required {
            return Ok(Err(refused(
                "checkpoint omits the scenario Open or selected Plan records",
            )));
        }
        let raw = match source.canonical_bytes() {
            Ok(raw) => raw,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut content_bytes = produced
            .bundle
            .bytes
            .len()
            .saturating_add(raw.len())
            .saturating_add(map.len())
            .saturating_add(128);
        if content_bytes > MAX_SCENARIO_MATH_BYTES {
            return Ok(Err(refused("scenario mathematical closure exceeds 64 MiB")));
        }
        let mut documents = Vec::with_capacity(document_oids.len());
        for oid in &document_oids {
            match self.read_document_for(capability, oid)? {
                Ok(DocumentRead::Full(document)) => {
                    if document.book_id != self.context().book_id || document.oid() != *oid {
                        return Ok(Err(refused(
                            "scenario document differs from its committed identity",
                        )));
                    }
                    content_bytes = content_bytes
                        .saturating_add(document.bytes.len())
                        .saturating_add(37);
                    if content_bytes > MAX_SCENARIO_MATH_BYTES {
                        return Ok(Err(refused("scenario mathematical closure exceeds 64 MiB")));
                    }
                    documents.push(ScenarioDocument {
                        oid: *oid,
                        kind: document.kind,
                        bytes: document.bytes,
                    });
                }
                Ok(DocumentRead::Redacted(_)) => {
                    return Ok(Err(refused(
                        "conditional scenario mathematics requires full assumption and cited-evidence bytes",
                    )));
                }
                Err(refusal) => return Ok(Err(refusal)),
            }
        }
        produced.bundle = match assemble(&raw, &produced.bundle.bytes, &map, &documents) {
            Ok(bundle) => bundle,
            Err(refusal) => return Ok(Err(refusal)),
        };
        produced.documents = document_oids.into_iter().collect();
        self.finish_scenario_math_bundle(principal, capability, PreparedScenarioMath { produced })
            .map(|outcome| outcome.map(Some))
    }
}
