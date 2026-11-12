//! Portable certificates for registered Lantern computations (plan §11.1/13.6).
//!
//! A native report certificate binds the complete journal/chart/calendar/unit
//! closure; a supplementary native Approval read binds the inputs used by JET.
//! V2 also binds REA populations and independently immutable attestations.
//! The outer certificate fixes the exact procedure, parameters, handles, recorded
//! frontier, effective cutoff, decision card and ordered findings. Decoding is an
//! integrity check, NOT a replay, signature, or independent completeness proof.
//! Current whole-book read/produce authority admits creation; current whole-book
//! read authority admits replay. Saved principal/commitment fields grant nothing.

mod bank;
mod extended;
pub use extended::EXTENDED_CERTIFIABLE_PROCEDURES;

use crate::{AsyncBook, BookError, Outcome, ReportCertificate, ReportSelection};
use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_lantern::{
    Cite, Coordinate, Finding, Params, ProcedureRun, Severity, Snapshot, Statistic, Work, catalog,
};
use fa_model::symbols::{label, property};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fa_registry::procedures::Claim;
use fa_time::DateDay;
use fgdb::{Database, NativeResultCertificate};
use fgdb_crypto::Hasher;
use fgdb_gql::{GqlParameters, GqlQueryPolicy};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};
use std::collections::{BTreeMap, BTreeSet};

pub const PROCEDURE_CERTIFICATE_FORMAT: &[u8] = b"fa:procedure-certificate:v1";
pub const EXTENDED_PROCEDURE_CERTIFICATE_FORMAT: &[u8] = extended::FORMAT;
pub const BANK_PROCEDURE_CERTIFICATE_FORMAT: &[u8] = bank::FORMAT;
pub const PROCEDURE_OUTPUT_FORMAT: &[u8] = b"fa:procedure-output:v1";
pub const MAX_PROCEDURE_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
const MAX_NATIVE: usize = 1024 * 1024;
const MAX_FINDINGS: usize = 100_000;
const CERTIFICATE_DOMAIN: &[u8] = b"fa:procedure-certificate-digest:v1";

/// Output-input closures audited for this certificate format. New catalog
/// procedures or semantic versions need their additional native inputs covered
/// before they can be certified here. This does not restrict ordinary runs.
pub const CERTIFIABLE_PROCEDURES: &[(&str, u16)] = &[
    ("jet.round_amounts", 1),
    ("jet.round_amounts", 2),
    ("jet.period_end_timing", 1),
    ("jet.period_end_timing", 2),
    ("jet.post_closing", 1),
    ("jet.weekend", 1),
    ("jet.self_approved", 1),
    ("jet.thin_descriptions", 1),
    ("duplicates.same_same_same", 1),
    ("duplicates.same_same_different", 1),
    // Reads what jet.thin_descriptions and the exact duplicate procedures
    // read: live postings' legs, descriptions and supersession lineage.
    ("duplicates.near", 1),
    ("numbers.sequence_gaps", 1),
    // Reads what jet.round_amounts reads: live postings' legs and units.
    ("numbers.round_amount_density", 1),
    ("benford.first_digit", 2),
    ("cutoff.period_boundary", 1),
    ("aging.open_items", 1),
    ("graph.round_trips", 2),
    ("graph.structuring", 2),
    ("trace.libr", 2),
    ("trace.fifo", 2),
    ("trace.lifo", 2),
    ("trace.pro_rata", 2),
    ("trace.network_fifo", 1),
    ("trace.network_lifo", 1),
    ("trace.network_libr", 1),
    ("trace.network_pro_rata", 1),
];

fn supported(id: &str, version: u16) -> bool {
    CERTIFIABLE_PROCEDURES.contains(&(id, version))
}

// This identity was registered with the original native input closure.
// Framing remains readable; request() still requires its original algorithm.
const RETAINED_ORIGINAL_CLOSURES: &[(&str, u16)] = &[("benford.first_digit", 1)];

/// Registered defaults are explicit data, not reselected when a certificate is
/// replayed. Callers can narrow/replace `parameters` with Params::set before use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureRequest {
    pub procedure: String,
    /// Pin a retained semantic version. `None` selects the current registry
    /// version; replay always supplies the certificate's original version.
    pub version: Option<u16>,
    pub parameters: Params,
    pub inputs: catalog::Inputs,
    pub known_at: Option<CommitSeq>,
    pub effective_through: Option<DateDay>,
    /// The run's work budget (fa-1tvm): the procedure stops at the first
    /// charge past it and the run is refused. `None` runs unbudgeted.
    pub budget: Option<u64>,
}

impl ProcedureRequest {
    pub fn new(procedure: &str, inputs: catalog::Inputs) -> Result<Self, fa_lantern::LanternError> {
        Ok(Self {
            procedure: procedure.into(),
            version: None,
            parameters: Params::defaults(procedure)?,
            inputs,
            known_at: None,
            effective_through: None,
            budget: None,
        })
    }

    fn build(&self) -> Result<Box<dyn fa_lantern::Procedure>, fa_lantern::LanternError> {
        match self.version {
            Some(version) => catalog::build_version(
                &self.procedure,
                version,
                self.parameters.clone(),
                self.inputs,
            ),
            None => catalog::build(&self.procedure, self.parameters.clone(), self.inputs),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureCertificate {
    source: ReportCertificate,
    approvals: NativeResultCertificate,
    extended_inputs: Vec<NativeResultCertificate>,
    registry: [u8; 32],
    producer: VId,
    capability_commitment: [u8; 32],
    report: ProcedureRun,
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedProcedure {
    pub report: ProcedureRun,
    pub certificate: ProcedureCertificate,
}

/// Whether the original procedure still returns the same analytical result and
/// decision evidence at the head, after its historical certificate replays.
///
/// This is deliberately conservative: population, work, findings, citations and
/// the complete decision card must still agree. A posting beyond a procedure's
/// effective cutoff can change its population or decision evidence even when
/// the selected findings do not change. Only the recorded frontier and its
/// input/finding commitments may differ for `Current`.
///
/// `Changed` carries the present run for inspection, not a new certificate or a
/// claim that the historical result is invalid. Neither outcome grants current
/// authority or authenticates an outsider's disclosure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcedureCertificateStatus {
    Current {
        checked_at: CommitSeq,
    },
    Changed {
        checked_at: CommitSeq,
        current: Box<ProcedureRun>,
    },
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §11.1/13.6; FA-INV-11 (native analytic inputs and exact output must replay)",
        "retain the complete procedure certificate and original book; replay with its registry/foundation versions and current whole-book read authority",
    )
}
fn offline_unsupported(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_notary::code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §11.1/13.3 (independent procedure replay requires its complete supported input and policy closure)",
        "export JET round-amount/period-end v1 or v2, exact duplicates v1, or first-digit Benford v2 with the original canonical registry closure and no input handles; only JET v2 permits an effective cutoff; replay other profiles in their original book",
    )
}

/// The signed payload of a historical Replacement does not identify its own
/// native vertex namespace. Only a later authenticated EntryRef can resolve
/// that ambiguity independently. Inspect the entire original recorded prefix,
/// before an effective cutoff removes any of its monetary rows.
pub(crate) fn check_offline_population(
    journal: &fa_notary::Journal,
    known_at: CommitSeq,
) -> fa_journal::refusal::Outcome<()> {
    use fa_model::{EntryClass, SupersessionKind};

    let unsupported = |message| {
        Refusal::new(
            fa_notary::code::SCOPE_UNSUPPORTED,
            exit::REFUSAL,
            message,
            "plan §8.2/11.1/13.3 (every corrected procedure input must preserve its authenticated identity and paired lineage)",
            "replay this retained procedure in its original book; portable replay requires an existing later authenticated reference to each canonical replacement within the certificate's original known-at prefix",
        )
    };
    if !journal.leaves.iter().any(|leaf| {
        leaf.envelope.is_entry()
            && leaf.envelope.commit_seq <= known_at
            && leaf.envelope.class == EntryClass::REPLACEMENT
    }) {
        return Ok(Ok(()));
    }
    let mut entries = BTreeMap::new();
    let mut replacements = BTreeMap::new();
    let mut reversals = BTreeMap::new();
    let mut references = BTreeMap::new();
    for leaf in journal
        .leaves
        .iter()
        .filter(|leaf| leaf.envelope.is_entry() && leaf.envelope.commit_seq <= known_at)
    {
        let fa_notary::Record::Entry(entry) = leaf.record()? else {
            continue;
        };
        let proposal = &entry.proposal;
        let at = leaf.envelope.commit_seq;
        let posted = proposal.class != EntryClass::PENDING && !proposal.legs.is_empty();
        if entries
            .insert(leaf.vid, (entry.entry_digest, at, posted))
            .is_some()
        {
            return Ok(Err(unsupported(
                "procedure population has duplicate entry identities",
            )));
        }
        if proposal.class == EntryClass::REPLACEMENT {
            let [supersession] = proposal.supersession.as_slice() else {
                return Ok(Err(unsupported(
                    "replacement requires one authenticated Replaces target",
                )));
            };
            if supersession.kind != SupersessionKind::Replaces
                || leaf.vid != fa_journal::rows::replacement_vid(supersession.target.vid)
                || !posted
            {
                return Ok(Err(unsupported(
                    "portable procedure replay does not support legacy or malformed replacement identities",
                )));
            }
            replacements.insert(leaf.vid, (entry.entry_digest, at, supersession.target));
        }
        for supersession in &proposal.supersession {
            if proposal.class == EntryClass::REVERSAL
                && supersession.kind == SupersessionKind::Reverses
                && reversals
                    .insert(
                        supersession.target.vid,
                        (supersession.target.entry_digest, at),
                    )
                    .is_some()
            {
                return Ok(Err(unsupported(
                    "procedure population has more than one reversal for an entry",
                )));
            }
            if matches!(
                (proposal.class, supersession.kind),
                (EntryClass::REVERSAL, SupersessionKind::Reverses)
                    | (EntryClass::REPLACEMENT, SupersessionKind::Replaces)
            ) {
                references
                    .entry((supersession.target.vid, supersession.target.entry_digest))
                    .and_modify(|latest: &mut CommitSeq| *latest = (*latest).max(at))
                    .or_insert(at);
            }
        }
        // Unactivated migration rows cannot resolve another row's identity.
        // Ordinary source visibility still follows the migration interpreter.
        if posted && proposal.class != EntryClass::MIGRATION {
            for settlement in proposal.legs.iter().flat_map(|leg| &leg.settles) {
                references
                    .entry((settlement.target.vid, settlement.target.entry_digest))
                    .and_modify(|latest: &mut CommitSeq| *latest = (*latest).max(at))
                    .or_insert(at);
            }
        }
    }
    for (identity, (digest, at, target)) in replacements {
        if !entries
            .get(&target.vid)
            .is_some_and(|(digest, target_at, posted)| {
                *digest == target.entry_digest && *target_at < at && *posted
            })
            || reversals.get(&target.vid) != Some(&(target.entry_digest, at))
        {
            return Ok(Err(unsupported(
                "replacement requires its earlier posted target and same-commit paired reversal",
            )));
        }
        if !references
            .get(&(identity, digest))
            .is_some_and(|latest| *latest > at)
        {
            return Ok(Err(unsupported(
                "replacement has no authenticated later reference resolving its original identity",
            )));
        }
    }
    Ok(Ok(()))
}

fn encode_error(e: fa_model::EncodeError) -> Refusal {
    invalid(format!("procedure encoding: {e}"))
}
fn decode_error(e: DecodeError) -> Refusal {
    invalid(format!("procedure decoding: {e}"))
}
fn lantern_error(e: fa_lantern::LanternError) -> Refusal {
    invalid(format!("procedure: {e}"))
}

/// The registries a procedure certificate binds, in commitment order.
const PROCEDURE_REGISTRIES: &[(&str, &str)] = &[
    (
        "procedures",
        include_str!("../../../registries/procedures.toml"),
    ),
    ("foundations", include_str!("../../../franken-stack.lock")),
];

/// The v2 closure over each registry's canonical content, so a comment or
/// layout edit never refuses a retained procedure certificate (bead fa-t8gk).
fn registry_digest() -> Result<[u8; 32], Refusal> {
    crate::certificate::canonical_closure(b"fa:procedure-registry:v2", PROCEDURE_REGISTRIES)
}

fn retained_registry_document() -> Result<Vec<u8>, Refusal> {
    let jet = fa_registry::procedures::legacy_v1_document()
        .and_then(fa_registry::procedures::solvency_v5_document)
        .and_then(fa_registry::procedures::lapping_v2_document)
        .map_err(|error| invalid(format!("retained JET registry: {error}")))?;
    let layering = fa_registry::procedures::layering_v2_document(jet)
        .map_err(|error| invalid(format!("retained layering registry: {error}")))?;
    fa_registry::procedures::suspense_v2_document(layering)
        .and_then(fa_registry::procedures::legacy_lookback_document)
        .map(|document| document.canonical_bytes())
        .map_err(|error| invalid(format!("published procedure registry: {error}")))
}

/// Exact canonical closure immediately before the two JET window laws became
/// v2. Other rows and the foundation remain bound, including for certificates
/// of unchanged procedures retained across this registry revision.
fn retained_registry_digest() -> Result<[u8; 32], Refusal> {
    registry_digest_with_procedures(retained_registry_document()?)
}

fn registry_digest_with_procedures(procedures: Vec<u8>) -> Result<[u8; 32], Refusal> {
    let foundations = fa_registry::toml::parse(include_str!("../../../franken-stack.lock"))
        .map_err(|error| invalid(format!("foundation registry: {error}")))?
        .canonical_bytes();
    let mut closure = Hasher::new();
    closure.update(b"fa:procedure-registry:v2");
    for (name, bytes) in [("procedures", procedures), ("foundations", foundations)] {
        closure.update(name.as_bytes());
        closure.update(&[0]);
        closure.update(&raw_digest(b"fa:registry-canonical-digest:v1", &bytes));
    }
    Ok(closure.finalize().0)
}

fn registry_digest_for_run(procedure: &str, version: u16) -> Result<[u8; 32], Refusal> {
    if version == 1 && matches!(procedure, "jet.round_amounts" | "jet.period_end_timing") {
        retained_registry_digest()
    } else if version == 2 && matches!(procedure, "graph.layering" | "graph.party_layering") {
        registry_digest_with_procedures(layering_v2_registry_document(false)?)
    } else if matches!(
        (procedure, version),
        ("lookback.preferences", 3) | ("lookback.fraudulent_transfer", 1)
    ) {
        registry_digest_with_procedures(legacy_lookback_registry_document()?)
    } else if procedure == "recon.lapping" && version == 2 {
        registry_digest_with_procedures(pre_lapping_registry_document()?.canonical_bytes())
    } else if procedure == "recon.lapping" && version == 3 {
        registry_digest_with_procedures(pre_lapping_metering_registry_document()?.canonical_bytes())
    } else if procedure == "solvency.cash_flow_test" && version == 5 {
        registry_digest_with_procedures(pre_solvency_registry_document()?.canonical_bytes())
    } else {
        registry_digest()
    }
}

fn layering_v2_registry_document(legacy_jet: bool) -> Result<Vec<u8>, Refusal> {
    let document = if legacy_jet {
        fa_registry::procedures::legacy_v1_document()
            .map_err(|error| invalid(format!("retained JET/layering registry: {error}")))?
    } else {
        fa_registry::toml::parse(PROCEDURE_REGISTRIES[0].1)
            .map_err(|error| invalid(format!("retained layering registry: {error}")))?
    };
    fa_registry::procedures::solvency_v5_document(document)
        .and_then(fa_registry::procedures::lapping_v2_document)
        .and_then(fa_registry::procedures::layering_v2_document)
        .and_then(fa_registry::procedures::legacy_lookback_document)
        .map(|document| document.canonical_bytes())
        .map_err(|error| invalid(format!("retained layering registry: {error}")))
}

fn legacy_lookback_registry_document() -> Result<Vec<u8>, Refusal> {
    let document = pre_lapping_registry_document()?;
    fa_registry::procedures::legacy_lookback_document(document)
        .map(|document| document.canonical_bytes())
        .map_err(|error| invalid(format!("retained lookback registry: {error}")))
}

fn legacy_lookback_registry_text() -> Result<String, Refusal> {
    fa_registry::procedures::legacy_lookback_registry_text(&pre_lapping_registry_text()?)
        .map_err(|error| invalid(format!("retained raw lookback registry: {error}")))
}

fn pre_lapping_registry_document() -> Result<fa_registry::toml::Document, Refusal> {
    let document = pre_solvency_registry_document()?;
    fa_registry::procedures::lapping_v2_document(document)
        .map_err(|error| invalid(format!("retained lapping registry: {error}")))
}

fn pre_lapping_registry_text() -> Result<String, Refusal> {
    fa_registry::procedures::lapping_v2_registry_text(&pre_solvency_registry_text()?)
        .map_err(|error| invalid(format!("retained raw lapping registry: {error}")))
}

/// Version 3's full-width arithmetic with its original certified work counters.
fn pre_lapping_metering_registry_document() -> Result<fa_registry::toml::Document, Refusal> {
    let document = pre_solvency_registry_document()?;
    fa_registry::procedures::lapping_v3_document(document)
        .map_err(|error| invalid(format!("retained lapping v3 registry: {error}")))
}

fn pre_lapping_metering_registry_text() -> Result<String, Refusal> {
    fa_registry::procedures::lapping_v3_registry_text(&pre_solvency_registry_text()?)
        .map_err(|error| invalid(format!("retained raw lapping v3 registry: {error}")))
}

fn pre_solvency_registry_document() -> Result<fa_registry::toml::Document, Refusal> {
    let document = fa_registry::toml::parse(PROCEDURE_REGISTRIES[0].1)
        .map_err(|error| invalid(format!("procedure registry: {error}")))?;
    fa_registry::procedures::solvency_v5_document(document)
        .map_err(|error| invalid(format!("retained cash-flow solvency registry: {error}")))
}

fn pre_solvency_registry_text() -> Result<String, Refusal> {
    fa_registry::procedures::solvency_v5_registry_text(PROCEDURE_REGISTRIES[0].1)
        .map_err(|error| invalid(format!("retained raw cash-flow solvency registry: {error}")))
}

/// The v1 raw-text closure, accepted only from certificates retained before
/// fa-t8gk; new certificates never carry it.
fn legacy_registry_digest() -> [u8; 32] {
    let sources: Vec<&[u8]> = PROCEDURE_REGISTRIES
        .iter()
        .map(|(_, text)| text.as_bytes())
        .collect();
    domain_digest(b"fa:procedure-registry:v1", &sources)
}

/// Preserve the existing raw-text compatibility path across this exact
/// semantic revision. The inverse is restricted to the two complete row
/// prefixes we changed; unknown layouts or versions are never guessed.
fn retained_legacy_registry_digest() -> Result<[u8; 32], Refusal> {
    let lookback = legacy_lookback_registry_text()?;
    let previous = fa_registry::procedures::layering_v2_registry_text(&lookback)
        .map_err(|error| invalid(format!("retained layering registry: {error}")))?;
    let jet = retained_jet_registry_text(&previous)?;
    let procedures = fa_registry::procedures::suspense_v2_registry_text(&jet)
        .map_err(|error| invalid(format!("published raw procedure registry: {error}")))?;
    Ok(domain_digest(
        b"fa:procedure-registry:v1",
        &[procedures.as_bytes(), PROCEDURE_REGISTRIES[1].1.as_bytes()],
    ))
}

fn retained_jet_registry_text(text: &str) -> Result<String, Refusal> {
    let mut procedures = text.to_string();
    for id in ["jet.round_amounts", "jet.period_end_timing"] {
        let current = format!(
            "[[procedure]]\nid = \"{id}\"\nversion = 2\neffective_through = \"optional\"\n"
        );
        if procedures.matches(&current).count() != 1 {
            return Err(invalid(
                "the original raw-text procedure registry is unavailable",
            ));
        }
        let previous = format!("[[procedure]]\nid = \"{id}\"\nversion = 1\n");
        procedures = procedures.replacen(&current, &previous, 1);
    }
    let reconstructed = fa_registry::toml::parse(&procedures)
        .map_err(|error| invalid(format!("retained raw procedure registry: {error}")))?
        .canonical_bytes();
    let expected = fa_registry::procedures::legacy_v1_document_from_text(text)
        .map_err(|error| invalid(format!("retained procedure registry: {error}")))?
        .canonical_bytes();
    if reconstructed != expected {
        return Err(invalid(
            "the retained raw and canonical procedure registries disagree",
        ));
    }
    Ok(procedures)
}

// Epoch order: JET, layering, suspense, preferences, fraudulent transfer,
// lapping, cash-flow solvency.
type ProcedureEpochVersions = (u16, u16, u16, u16, u16, u16, u16);

/// Only these eight audited epochs are executable, with algorithm identities
/// checked separately. Unpublished mixed combinations are never inferred.
fn registry_versions(registry: &[u8; 32]) -> Result<Option<ProcedureEpochVersions>, Refusal> {
    let epochs = [
        (2, 3, 3, 4, 2, 4, 6),
        (2, 3, 3, 4, 2, 4, 5),
        (2, 3, 3, 4, 2, 3, 5),
        (2, 3, 3, 4, 2, 2, 5),
        (2, 3, 3, 3, 1, 2, 5),
        (2, 2, 3, 3, 1, 2, 5),
        (1, 2, 3, 3, 1, 2, 5),
        (1, 2, 2, 3, 1, 2, 5),
    ];
    for (jet, layering, suspense, preference, fraud, lapping, solvency) in epochs {
        let canonical = if solvency == 6 {
            registry_digest()?
        } else if lapping == 4 {
            registry_digest_with_procedures(pre_solvency_registry_document()?.canonical_bytes())?
        } else if lapping == 3 {
            registry_digest_with_procedures(
                pre_lapping_metering_registry_document()?.canonical_bytes(),
            )?
        } else if preference == 4 {
            registry_digest_with_procedures(pre_lapping_registry_document()?.canonical_bytes())?
        } else if suspense == 2 {
            retained_registry_digest()?
        } else if layering == 3 {
            registry_digest_with_procedures(legacy_lookback_registry_document()?)?
        } else {
            registry_digest_with_procedures(layering_v2_registry_document(jet == 1)?)?
        };
        if registry == &canonical {
            return Ok(Some((
                jet, layering, suspense, preference, fraud, lapping, solvency,
            )));
        }
    }
    // Canonical epochs do not depend on the stricter raw-text layout inverse.
    for (jet, layering, suspense, preference, fraud, lapping, solvency) in epochs {
        let raw = if solvency == 6 {
            legacy_registry_digest()
        } else if lapping == 4 {
            domain_digest(
                b"fa:procedure-registry:v1",
                &[
                    pre_solvency_registry_text()?.as_bytes(),
                    PROCEDURE_REGISTRIES[1].1.as_bytes(),
                ],
            )
        } else if lapping == 3 {
            domain_digest(
                b"fa:procedure-registry:v1",
                &[
                    pre_lapping_metering_registry_text()?.as_bytes(),
                    PROCEDURE_REGISTRIES[1].1.as_bytes(),
                ],
            )
        } else if preference == 4 {
            domain_digest(
                b"fa:procedure-registry:v1",
                &[
                    pre_lapping_registry_text()?.as_bytes(),
                    PROCEDURE_REGISTRIES[1].1.as_bytes(),
                ],
            )
        } else if suspense == 2 {
            retained_legacy_registry_digest()?
        } else {
            let text = legacy_lookback_registry_text()?;
            let text = if layering == 2 {
                fa_registry::procedures::layering_v2_registry_text(&text)
                    .map_err(|error| invalid(format!("retained layering registry: {error}")))?
            } else {
                text
            };
            let text = if jet == 1 {
                retained_jet_registry_text(&text)?
            } else {
                text
            };
            domain_digest(
                b"fa:procedure-registry:v1",
                &[text.as_bytes(), PROCEDURE_REGISTRIES[1].1.as_bytes()],
            )
        };
        if registry == &raw {
            return Ok(Some((
                jet, layering, suspense, preference, fraud, lapping, solvency,
            )));
        }
    }
    Ok(None)
}

fn canonical_registry_document(registry: &[u8; 32]) -> Result<Option<Vec<u8>>, Refusal> {
    if registry == &registry_digest()? {
        return fa_registry::toml::parse(PROCEDURE_REGISTRIES[0].1)
            .map(|document| Some(document.canonical_bytes()))
            .map_err(|error| invalid(format!("procedure registry: {error}")));
    }
    let solvency = pre_solvency_registry_document()?.canonical_bytes();
    if registry == &registry_digest_with_procedures(solvency.clone())? {
        return Ok(Some(solvency));
    }
    let metering = pre_lapping_metering_registry_document()?.canonical_bytes();
    if registry == &registry_digest_with_procedures(metering.clone())? {
        return Ok(Some(metering));
    }
    let lapping = pre_lapping_registry_document()?.canonical_bytes();
    if registry == &registry_digest_with_procedures(lapping.clone())? {
        return Ok(Some(lapping));
    }
    let lookback = legacy_lookback_registry_document()?;
    if registry == &registry_digest_with_procedures(lookback.clone())? {
        return Ok(Some(lookback));
    }
    let jet = retained_registry_document()?;
    if registry == &registry_digest_with_procedures(jet.clone())? {
        return Ok(Some(jet));
    }
    for legacy_jet in [false, true] {
        let document = layering_v2_registry_document(legacy_jet)?;
        if registry == &registry_digest_with_procedures(document.clone())? {
            return Ok(Some(document));
        }
    }
    Ok(None)
}
fn approval_statement(at: CommitSeq) -> String {
    format!(
        "MATCH (n:Approval) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n._fa_payload,n._fa_digest ORDER BY n",
        at.0
    )
}
fn policy() -> GqlQueryPolicy {
    GqlQueryPolicy::new(10_000_000, 1_000_000, 256 * 1024 * 1024, 256 * 1024 * 1024)
}
fn raw_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().0
}

fn check_run(run: &ProcedureRun) -> Result<(), Refusal> {
    if run.procedure.is_empty()
        || run.procedure.len() > 128
        || run.version == 0
        || run.evidence.len() > 128
        || run.parameters.len() > 128
        || run.inputs.len() > 16
        || run.findings.len() > MAX_FINDINGS
    {
        return Err(invalid("procedure record exceeds its field bounds"));
    }
    for values in [
        run.parameters
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        run.inputs.iter().map(|(k, _)| k.as_str()).collect(),
    ] {
        if values.iter().any(|k| k.is_empty() || k.len() > 128)
            || values.windows(2).any(|p| p[0] >= p[1])
        {
            return Err(invalid(
                "procedure parameter/input names must be unique and ordered",
            ));
        }
    }
    if run.inputs.iter().any(|(_, v)| v.len() > 256) {
        return Err(invalid("oversized procedure handle"));
    }
    let mut w = Writer::new();
    w.str(&run.procedure).u16(run.version);
    w.list(&run.parameters, |w, (k, v)| {
        w.str(k).i128(*v);
    });
    w.list(&run.inputs, |w, (k, v)| {
        w.str(k).str(v);
    });
    if raw_digest(
        fa_lantern::PARAMETERS_DIGEST_DOMAIN,
        &w.finish().map_err(encode_error)?,
    ) != run.parameters_digest
    {
        return Err(invalid(
            "procedure parameters/handles do not match their digest",
        ));
    }
    let mut previous: Option<(Severity, i128, Vec<Vec<u8>>, &str)> = None;
    let mut finding_bytes = 0usize;
    for finding in &run.findings {
        if finding.procedure != run.procedure
            || finding.version != run.version
            || finding.cites.len() > fa_lantern::MAX_CITES
            || finding.narrative.len() > fa_lantern::MAX_NARRATIVE_BYTES
            || finding.statistic.name.len() > 128
        {
            return Err(invalid(
                "finding identity or field bounds disagree with the run",
            ));
        }
        // Check aggregate size before encoding all findings into a single buffer.
        let bytes = fa_lantern::finding_bytes(finding).map_err(lantern_error)?;
        finding_bytes = finding_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("finding size overflow"))?;
        if finding_bytes > MAX_OUTPUT {
            return Err(invalid("procedure findings exceed the output bound"));
        }
        let cites = finding
            .cites
            .iter()
            .map(Cite::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(encode_error)?;
        let current = (
            finding.severity,
            finding.statistic.value,
            cites,
            finding.narrative.as_str(),
        );
        if let Some(prior) = &previous {
            let order = current
                .0
                .cmp(&prior.0)
                .then(current.1.cmp(&prior.1))
                .then_with(|| prior.2.cmp(&current.2))
                .then_with(|| prior.3.cmp(current.3));
            if order.is_gt() {
                return Err(invalid("findings are not in canonical ranking order"));
            }
        }
        previous = Some(current);
    }
    let mut w = Writer::new();
    w.str(&run.procedure)
        .u16(run.version)
        .fixed(&run.parameters_digest)
        .fixed(&run.inputs_digest);
    run.coordinate.encode(&mut w);
    w.list(&run.findings, |w, f| f.encode(w));
    if raw_digest(
        fa_lantern::FINDINGS_DIGEST_DOMAIN,
        &w.finish().map_err(encode_error)?,
    ) != run.findings_digest
    {
        return Err(invalid("procedure findings do not match their digest"));
    }
    if run.decision_card.digest().map_err(encode_error)? != run.decision_card_digest {
        return Err(invalid("procedure decision card digest differs"));
    }
    Ok(())
}

fn encode_run(run: &ProcedureRun) -> Result<Vec<u8>, Refusal> {
    check_run(run)?;
    let mut w = Writer::new();
    w.bytes(PROCEDURE_OUTPUT_FORMAT)
        .str(&run.procedure)
        .u16(run.version)
        .u8(match run.claim {
            Claim::Statistical => 0,
            Claim::Invariant => 1,
        })
        .str(&run.evidence);
    run.coordinate.encode(&mut w);
    w.list(&run.parameters, |w, (k, v)| {
        w.str(k).i128(*v);
    });
    w.list(&run.inputs, |w, (k, v)| {
        w.str(k).str(v);
    });
    w.fixed(&run.parameters_digest)
        .fixed(&run.inputs_digest)
        .u64(run.population)
        .u64(run.work.entries)
        .u64(run.work.legs)
        .u64(run.work.comparisons);
    w.list(&run.findings, |w, f| f.encode(w));
    w.fixed(&run.findings_digest)
        .bytes(&run.decision_card.canonical_bytes().map_err(encode_error)?)
        .fixed(&run.decision_card_digest);
    let bytes = w.finish().map_err(encode_error)?;
    if bytes.len() > MAX_OUTPUT {
        return Err(invalid("procedure output exceeds 32 MiB"));
    }
    Ok(bytes)
}

fn decode_run(bytes: &[u8]) -> Result<ProcedureRun, Refusal> {
    if bytes.len() > MAX_OUTPUT {
        return Err(invalid("procedure output exceeds 32 MiB"));
    }
    let read = || -> Result<ProcedureRun, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.bytes(64, "procedure output format")? != PROCEDURE_OUTPUT_FORMAT {
            return Err(r.invalid("procedure output format"));
        }
        let procedure = r.str(128, "procedure")?.to_string();
        let version = r.u16("procedure version")?;
        let claim = match r.u8("claim")? {
            0 => Claim::Statistical,
            1 => Claim::Invariant,
            t => return Err(r.bad_tag("claim", t)),
        };
        let evidence = r.str(128, "evidence")?.to_string();
        let coordinate = Coordinate {
            book_id: Id128(r.fixed("book")?),
            known_at: CommitSeq(r.u64("known-at")?),
            effective_through: r.opt("effective cutoff", |r| Ok(DateDay(r.i32("day")?)))?,
        };
        let parameters = r.list(128, "parameters", |r| {
            Ok((r.str(128, "parameter")?.to_string(), r.i128("value")?))
        })?;
        let inputs = r.list(16, "inputs", |r| {
            Ok((
                r.str(128, "input")?.to_string(),
                r.str(256, "handle")?.to_string(),
            ))
        })?;
        let parameters_digest = r.fixed("parameter digest")?;
        let inputs_digest = r.fixed("inputs digest")?;
        let population = r.u64("population")?;
        let work = Work {
            entries: r.u64("work entries")?,
            legs: r.u64("work legs")?,
            comparisons: r.u64("work comparisons")?,
        };
        let findings = r.list(MAX_FINDINGS, "findings", |r| {
            let procedure = r.str(128, "finding procedure")?.to_string();
            let version = r.u16("finding version")?;
            let tag = r.u8("severity")?;
            let severity = Severity::from_tag(tag).ok_or_else(|| r.bad_tag("severity", tag))?;
            let statistic = Statistic {
                name: r.str(128, "statistic name")?.to_string(),
                value: r.i128("statistic value")?,
                scale: r.u8("scale")?,
                population: r.u64("statistic population")?,
            };
            let cites = r.list(fa_lantern::MAX_CITES, "citations", Cite::decode)?;
            let narrative = r
                .str(fa_lantern::MAX_NARRATIVE_BYTES, "narrative")?
                .to_string();
            Ok(Finding {
                procedure,
                version,
                severity,
                statistic,
                cites,
                narrative,
            })
        })?;
        let findings_digest = r.fixed("findings digest")?;
        let decision_card = fa_policy::DecisionCard::decode(r.bytes(MAX_NATIVE, "decision card")?)?;
        let decision_card_digest = r.fixed("decision digest")?;
        r.finish()?;
        Ok(ProcedureRun {
            procedure,
            version,
            claim,
            evidence,
            coordinate,
            parameters,
            inputs,
            parameters_digest,
            inputs_digest,
            population,
            work,
            findings,
            findings_digest,
            decision_card,
            decision_card_digest,
        })
    };
    let run = read().map_err(decode_error)?;
    if encode_run(&run)?.as_slice() != bytes {
        return Err(invalid("noncanonical procedure output"));
    }
    Ok(run)
}

impl ProcedureCertificate {
    /// Independent replay accepts bounded JET, exact-duplicate and Benford profiles.
    /// Native replay continues to support the wider catalog and legacy hashes.
    pub(crate) fn check_offline_profile(&self) -> Result<(), Refusal> {
        let duplicates = self.report.procedure == "duplicates.same_same_same";
        let benford = self.report.procedure == "benford.first_digit";
        let post_closing = self.report.procedure == "jet.post_closing";
        let supported = match self.report.procedure.as_str() {
            "jet.round_amounts" | "jet.period_end_timing" => matches!(self.report.version, 1 | 2),
            "jet.post_closing" | "duplicates.same_same_same" => {
                self.report.version == 1 && self.report.parameters.is_empty()
            }
            "benford.first_digit" => {
                let bounds = [
                    ("account_type", 0, 8),
                    ("currency_iso4217", 1, 999),
                    ("mad_acceptable", 0, i128::from(u32::MAX)),
                    ("mad_close", 0, i128::from(u32::MAX)),
                    ("mad_marginal", 0, i128::from(u32::MAX)),
                    ("min_population", 0, i128::from(u32::MAX)),
                    ("side", 0, 1),
                ];
                self.report.version == 2
                    && self.report.parameters.len() == bounds.len()
                    && self.report.parameters.iter().zip(bounds).all(
                        |((name, value), (expected, low, high))| {
                            name == expected && (low..=high).contains(value)
                        },
                    )
            }
            _ => false,
        };
        if self.format() != PROCEDURE_CERTIFICATE_FORMAT
            || !supported
            || ((self.report.version == 1 || benford)
                && self.report.coordinate.effective_through.is_some())
            || !self.report.inputs.is_empty()
        {
            return Err(offline_unsupported(
                "portable profiles are JET round-amount/period-end v1/v2, post-closing v1, exact duplicates v1, and first-digit Benford v2 with its complete parameter inventory; only round-amount/period-end v2 supports an effective cutoff and no profile supports input handles",
            ));
        }
        if canonical_registry_document(&self.registry)?.is_none()
            || !registry_versions(&self.registry)?.is_some_and(|versions| {
                duplicates || benford || post_closing || versions.0 == self.report.version
            })
        {
            return Err(offline_unsupported(
                "portable procedures require their version's original canonical procedure registry closure; legacy raw-text commitments cannot be substituted",
            ));
        }
        Ok(())
    }

    /// Extend the original native registry closure without substituting a
    /// newer foundation. The policy document lets an independent verifier
    /// derive the policy OID used by the complete decision-card transcript.
    pub(crate) fn offline_registry_documents(
        &self,
        mut native: Vec<(String, Vec<u8>)>,
    ) -> Result<Vec<(String, Vec<u8>)>, Refusal> {
        self.check_offline_profile()?;
        let expected = ["account_types", "entry_classes", "units", "foundations"];
        if native.iter().map(|(name, _)| name.as_str()).ne(expected) {
            return Err(offline_unsupported(
                "portable procedures require their complete original four-document native registry closure",
            ));
        }
        let canonical = |name: &str, text: &str| {
            fa_registry::toml::parse(text)
                .map(|document| document.canonical_bytes())
                .map_err(|error| {
                    invalid(format!("embedded registry {name} does not parse: {error}"))
                })
        };
        if native[3].1 != canonical("foundations", include_str!("../../../franken-stack.lock"))? {
            return Err(offline_unsupported(
                "the native source and procedure certificate require different foundation registries",
            ));
        }
        let procedures = canonical_registry_document(&self.registry)?.ok_or_else(|| {
            offline_unsupported("portable procedure registry content is unavailable")
        })?;
        native.push(("procedures".into(), procedures));
        native.push((
            "sod_policy".into(),
            canonical(
                "sod_policy",
                include_str!("../../../registries/sod_policy.toml"),
            )?,
        ));
        Ok(native)
    }

    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        &self.source
    }
    #[must_use]
    pub fn report(&self) -> &ProcedureRun {
        &self.report
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
    pub fn producer(&self) -> VId {
        self.producer
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }
    /// Original procedures use v1. Extended procedures carry six additional
    /// native population witnesses and use v2. Bank drift uses its complete v3
    /// native populations and relations; no earlier format is auto-upgraded.
    #[must_use]
    pub fn format(&self) -> &'static [u8] {
        if bank::supported(&self.report.procedure, self.report.version) {
            bank::FORMAT
        } else if self.extended_inputs.is_empty() {
            PROCEDURE_CERTIFICATE_FORMAT
        } else {
            extended::FORMAT
        }
    }
    #[must_use]
    pub fn supplemental_inputs(&self) -> &[NativeResultCertificate] {
        &self.extended_inputs
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at
    }
    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.source.book_id
    }

    fn body(&self) -> Result<Vec<u8>, Refusal> {
        if self.source.branch_id != Id128::TRUNK
            || self.source.time_selection.is_some()
            || self.source.selection != (ReportSelection::OpenItems { account: None })
            || self.report.coordinate.book_id != self.source.book_id
            || self.report.coordinate.known_at != self.source.known_at
        {
            return Err(invalid(
                "procedure and complete native source coordinates disagree",
            ));
        }
        if bank::supported(&self.report.procedure, self.report.version) {
            bank::validate(self)?;
        } else {
            extended::validate(self)?;
        }
        let source = self.source.canonical_bytes().map_err(encode_error)?;
        ReportCertificate::decode(&source)?;
        let native = self.approvals.canonical_bytes();
        let basis = self
            .source
            .inputs
            .first()
            .ok_or_else(|| invalid("missing native source"))?;
        if native.len() > MAX_NATIVE
            || self.approvals.statement != approval_statement(self.known_at())
            || self.approvals.plan.snapshot_seq != self.known_at()
            || self.approvals.snapshot_identity != basis.snapshot_identity
            || self.approvals.database_identity != basis.database_identity
        {
            return Err(invalid(
                "approval read is not the same certified native snapshot",
            ));
        }
        if encode_run(&self.report)? != self.output {
            return Err(invalid("procedure output record differs"));
        }
        let supplementary = if self.extended_inputs.is_empty() {
            0
        } else {
            4 + self
                .extended_inputs
                .iter()
                .map(|input| 4 + input.canonical_bytes().len())
                .sum::<usize>()
        };
        let total = source
            .len()
            .checked_add(native.len())
            .and_then(|n| n.checked_add(self.output.len()))
            .and_then(|n| {
                n.checked_add(4 + self.format().len() + 4 * 3 + 32 * 3 + 16 + supplementary)
            })
            .ok_or_else(|| invalid("procedure certificate length overflow"))?;
        if total > MAX_PROCEDURE_CERTIFICATE_BYTES {
            return Err(invalid("procedure certificate exceeds 64 MiB"));
        }
        let mut w = Writer::with_capacity(total);
        w.bytes(self.format()).bytes(&source).bytes(&native);
        if !self.extended_inputs.is_empty() {
            w.list(&self.extended_inputs, |w, input| {
                w.bytes(&input.canonical_bytes());
            });
        }
        w.fixed(&self.registry)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        w.finish().map_err(encode_error)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body()?;
        if domain_digest(CERTIFICATE_DOMAIN, &[&bytes]) != self.digest {
            return Err(invalid("procedure certificate digest differs"));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_PROCEDURE_CERTIFICATE_BYTES {
            return Err(invalid("procedure certificate exceeds 64 MiB"));
        }
        let mut r = Reader::new(bytes);
        let format = r
            .bytes(64, "procedure certificate format")
            .map_err(decode_error)?;
        if format != PROCEDURE_CERTIFICATE_FORMAT
            && format != extended::FORMAT
            && format != bank::FORMAT
        {
            return Err(invalid("unsupported procedure certificate version"));
        }
        let source = ReportCertificate::decode(
            r.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "native source")
                .map_err(decode_error)?,
        )?;
        let approvals = NativeResultCertificate::decode(
            r.bytes(MAX_NATIVE, "approval source")
                .map_err(decode_error)?,
        )
        .map_err(|_| invalid("malformed native approval source"))?;
        let mut extended_inputs = Vec::new();
        if format == extended::FORMAT || format == bank::FORMAT {
            let required = if format == bank::FORMAT {
                bank::COUNT
            } else {
                extended::COUNT
            };
            let count = r
                .count(required, "extended native inputs")
                .map_err(decode_error)?;
            if count != required {
                return Err(invalid("incomplete extended native input closure"));
            }
            for _ in 0..count {
                extended_inputs.push(
                    NativeResultCertificate::decode(
                        r.bytes(MAX_NATIVE, "extended native source")
                            .map_err(decode_error)?,
                    )
                    .map_err(|_| invalid("malformed extended native input"))?,
                );
            }
        }
        let registry = r.fixed("registry").map_err(decode_error)?;
        let producer = VId(r.u128("producer").map_err(decode_error)?);
        let capability_commitment = r.fixed("capability commitment").map_err(decode_error)?;
        let output = r
            .bytes(MAX_OUTPUT, "procedure output")
            .map_err(decode_error)?
            .to_vec();
        let report = decode_run(&output)?;
        let digest = r.fixed("certificate digest").map_err(decode_error)?;
        r.finish().map_err(decode_error)?;
        let certificate = Self {
            source,
            approvals,
            extended_inputs,
            registry,
            producer,
            capability_commitment,
            report,
            output,
            digest,
        };
        if certificate.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical procedure certificate"));
        }
        Ok(certificate)
    }
    fn request(&self) -> Result<ProcedureRequest, Refusal> {
        if !supported(&self.report.procedure, self.report.version)
            && !RETAINED_ORIGINAL_CLOSURES
                .contains(&(self.report.procedure.as_str(), self.report.version))
            && !extended::has_retained_closure(&self.report.procedure, self.report.version)
            && !bank::supported(&self.report.procedure, self.report.version)
        {
            return Err(invalid(
                "this procedure version has no complete registered native certificate closure",
            ));
        }
        let current = registry_digest()?;
        let Some((
            jet_version,
            layering_version,
            suspense_version,
            preference_version,
            fraud_version,
            lapping_version,
            solvency_version,
        )) = registry_versions(&self.registry)?
        else {
            return Err(crate::certificate::registry_unavailable(
                "procedure certificate",
                &self.registry,
                &current,
                PROCEDURE_REGISTRIES,
            ));
        };
        let declared_version = match self.report.procedure.as_str() {
            "jet.round_amounts" | "jet.period_end_timing" => Some(jet_version),
            "graph.layering" | "graph.party_layering" => Some(layering_version),
            "jet.suspense_aging" => Some(suspense_version),
            "lookback.preferences" => Some(preference_version),
            "lookback.fraudulent_transfer" => Some(fraud_version),
            "recon.lapping" => Some(lapping_version),
            "solvency.cash_flow_test" => Some(solvency_version),
            _ => None,
        };
        if declared_version.is_some_and(|version| version != self.report.version) {
            return Err(invalid(
                "procedure registry does not declare this algorithm version",
            ));
        }
        let mut request = ProcedureRequest::new(&self.report.procedure, catalog::Inputs::default())
            .map_err(lantern_error)?;
        request.version = Some(self.report.version);
        let row = fa_lantern::bind_version(&self.report.procedure, self.report.version).map_err(
            |error| match error {
                fa_lantern::LanternError::Version { .. } => {
                    invalid("procedure identity, claim, evidence or full parameter set has changed")
                }
                other => lantern_error(other),
            },
        )?;
        if row.version != self.report.version
            || row.claim != self.report.claim
            || row.evidence != self.report.evidence
            || request
                .parameters
                .values()
                .iter()
                .map(|(k, _)| k)
                .collect::<Vec<_>>()
                != self
                    .report
                    .parameters
                    .iter()
                    .map(|(k, _)| k)
                    .collect::<Vec<_>>()
        {
            return Err(invalid(
                "procedure identity, claim, evidence or full parameter set has changed",
            ));
        }
        for (name, value) in &self.report.parameters {
            request.parameters = request
                .parameters
                .set(name, *value)
                .map_err(lantern_error)?;
        }
        for (name, value) in &self.report.inputs {
            if value.len() != 32
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("noncanonical procedure handle"));
            }
            let id = VId(u128::from_str_radix(value, 16).map_err(|_| invalid("procedure handle"))?);
            match name.as_str() {
                "account" => request.inputs.account = Some(id),
                "source" => request.inputs.source = Some(id),
                _ => return Err(invalid("unsupported procedure input")),
            }
        }
        let built = request.build().map_err(lantern_error)?;
        if built.inputs() != self.report.inputs {
            return Err(invalid("procedure declared handles differ"));
        }
        request.known_at = Some(self.known_at());
        request.effective_through = self.report.coordinate.effective_through;
        Ok(request)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    produce: bool,
    reconcile: bool,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .and_then(|()| {
            if reconcile {
                fa_policy::require(
                    capability,
                    Op::Reconcile,
                    "reading bank reconciliation procedures",
                )
            } else {
                Ok(())
            }
        })
        .and_then(|()| {
            if produce {
                fa_policy::require(capability, Op::Produce, "certifying a procedure")
            } else {
                Ok(())
            }
        })
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    book.query(cx, |db, context| {
        let head = db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        Ok(fa_journal::policy::capability_admitted(
            db, context, capability,
        )?)
    })
}

/// Approval objects are immutable, outside the posting Entry accumulator.
/// Their historical payload is also required to remain unchanged at HEAD.
fn unchanged_approvals<V: Vfs + Clone>(db: &Database<V>, snapshot: &Snapshot) -> Outcome<()> {
    use fa_journal::rows::bytes;
    let head = db.frontier().map_err(KernelError::from)?;
    let mut seen = BTreeSet::new();
    for entry in &snapshot.entries {
        for cited in &entry.entry.approvals {
            if !seen.insert(cited.approval_vid) {
                continue;
            }
            let Some(old) = db
                .vertex_at(cited.approval_vid, snapshot.coordinate.known_at)
                .map_err(KernelError::from)?
            else {
                return Ok(Err(invalid("historical procedure approval is missing")));
            };
            let Some(now) = db
                .vertex_at(cited.approval_vid, head)
                .map_err(KernelError::from)?
            else {
                return Ok(Err(invalid("procedure approval was retired")));
            };
            let old_payload = bytes(&old, property::FA_PAYLOAD, "approval payload")?;
            let old_digest = bytes(&old, property::FA_DIGEST, "approval digest")?;
            let approval = fa_policy::Approval::decode(&old_payload)
                .map_err(|e| BookError::Kernel(KernelError::Model(e.into())))?;
            let digest = approval
                .digest()
                .map_err(|e| BookError::Kernel(KernelError::Model(e.into())))?;
            if !old.labels.contains(&label::APPROVAL)
                || now.labels != old.labels
                || now.created_at != old.created_at
                || approval.book_id != snapshot.coordinate.book_id
                || old_digest.as_slice() != digest
                || approval.approved_proposal_digest != cited.approved_digest
                || fa_journal::policy::approval_vid(
                    approval.book_id,
                    approval.principal,
                    &approval.approved_proposal_digest,
                    approval.security_policy_epoch,
                ) != cited.approval_vid
                || bytes(&now, property::FA_PAYLOAD, "current approval payload")? != old_payload
                || bytes(&now, property::FA_DIGEST, "current approval digest")? != old_digest
            {
                return Ok(Err(invalid(
                    "a procedure approval was rebound or rewritten",
                )));
            }
        }
    }
    Ok(Ok(()))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Hydrate the native history needed by a procedure only after current
    /// admission. Bank drift needs the original birth and correction history
    /// even when its output selects HEAD. No accounting record is published.
    pub async fn prepare_procedure_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        procedure: &str,
        produce: bool,
    ) -> Outcome<()> {
        let reconcile = procedure == bank::PROCEDURE;
        if let Err(refusal) = authorize(self, cx, principal, capability, produce, reconcile)? {
            return Ok(Err(refusal));
        }
        if reconcile
            && let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await?
        {
            return Ok(Err(refusal));
        }
        authorize(self, cx, principal, capability, produce, reconcile)
    }

    /// Run with explicit current authority and admitted history hydration.
    /// Unlike certification, execution requires no Produce grant. The original
    /// capability-free runner cannot manufacture native bank reconciliation
    /// inputs and continues to refuse that procedure.
    pub async fn run_procedure_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &ProcedureRequest,
    ) -> Outcome<ProcedureRun> {
        if let Err(refusal) = self
            .prepare_procedure_history(cx, principal, capability, &request.procedure, false)
            .await?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, request.known_at)
            .await?
        {
            return Ok(Err(refusal));
        }
        let built = match request.build() {
            Ok(procedure) => procedure,
            Err(error) => return Ok(Err(lantern_error(error))),
        };
        let row = fa_lantern::bind_version(built.id(), built.version())?;
        for (name, present) in [
            ("account", request.inputs.account.is_some()),
            ("source", request.inputs.source.is_some()),
        ] {
            if present != row.inputs.iter().any(|input| input.name == name) {
                return Ok(Err(invalid(
                    "procedure handles must exactly match its declared inputs",
                )));
            }
        }
        let reconcile = request.procedure == bank::PROCEDURE;
        let result = self.query(cx, |db, book| {
            let mut snapshot = Snapshot::read(
                db,
                &cx.query(),
                book,
                request.known_at,
                request.effective_through,
            )?;
            if reconcile
                && let Err(refusal) = bank::populate(db, cx, book, capability, &mut snapshot)?
            {
                return Ok(Err(refusal));
            }
            Ok(Ok(fa_lantern::run_over_metered(
                &snapshot,
                book,
                built.as_ref(),
                request.budget,
                Some(&cx.query()),
            )?))
        })?;
        if let Err(refusal) = authorize(self, cx, principal, capability, false, reconcile)? {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Create a certificate from a cold or resident book. Read, Reconcile for
    /// bank inputs, and Produce all precede native history hydration.
    pub async fn certify_procedure_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &ProcedureRequest,
    ) -> Outcome<CertifiedProcedure> {
        if let Err(refusal) = self
            .prepare_procedure_history(cx, principal, capability, &request.procedure, true)
            .await?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, request.known_at)
            .await?
        {
            return Ok(Err(refusal));
        }
        self.certify_procedure(cx, principal, capability, request)
    }

    /// Replay the saved coordinate after loading authenticated native history.
    /// Saved producer fields never supply current Reconcile authority.
    pub async fn replay_procedure_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &ProcedureCertificate,
    ) -> Outcome<ProcedureRun> {
        if let Err(refusal) = self
            .prepare_procedure_history(
                cx,
                principal,
                capability,
                &certificate.report.procedure,
                false,
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, Some(certificate.known_at()))
            .await?
        {
            return Ok(Err(refusal));
        }
        self.replay_procedure(cx, principal, capability, certificate)
    }

    /// Check freshness from a cold or resident book. Current Read and any bank
    /// Reconcile authority precede history hydration; saved producer fields
    /// supply neither. The retained certificate is replayed before reading the
    /// current result, and no accounting record or certificate is published.
    pub async fn procedure_certificate_status_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &ProcedureCertificate,
    ) -> Outcome<ProcedureCertificateStatus> {
        if let Err(refusal) = self
            .prepare_procedure_history(
                cx,
                principal,
                capability,
                &certificate.report.procedure,
                false,
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, Some(certificate.known_at()))
            .await?
        {
            return Ok(Err(refusal));
        }
        self.procedure_certificate_status(cx, principal, capability, certificate)
    }

    /// Replay the complete historical run, then execute its exact registered
    /// method, parameters, handles and effective cutoff at one current head.
    /// Read is sufficient; bank procedures additionally require Reconcile.
    ///
    /// Unlike monetary report freshness, this compares the run itself rather
    /// than attributing changes to later posting entries: parties, approvals,
    /// attestations and bank decisions can also change analytical results.
    pub fn procedure_certificate_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &ProcedureCertificate,
    ) -> Outcome<ProcedureCertificateStatus> {
        let original = match self.replay_procedure(cx, principal, capability, certificate)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let built = request.build()?;
        let bank_procedure = request.procedure == bank::PROCEDURE;
        let result = self.query(cx, |db, book| {
            let mut snapshot =
                Snapshot::read(db, &cx.query(), book, None, request.effective_through)?;
            if bank_procedure
                && let Err(refusal) = bank::populate(db, cx, book, capability, &mut snapshot)?
            {
                return Ok(Err(refusal));
            }
            if extended::supported(&original.procedure, original.version)
                && let Err(refusal) = extended::unchanged_attestations(db, cx, &snapshot)?
            {
                return Ok(Err(refusal));
            }
            if let Err(refusal) = unchanged_approvals(db, &snapshot)? {
                return Ok(Err(refusal));
            }
            Ok(Ok(fa_lantern::run_over_metered(
                &snapshot,
                book,
                built.as_ref(),
                None,
                Some(&cx.query()),
            )?))
        })?;
        if let Err(refusal) = authorize(self, cx, principal, capability, false, bank_procedure)? {
            return Ok(Err(refusal));
        }
        let current = match result {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        let checked_at = current.coordinate.known_at;
        // Both commitments include the recorded frontier, so a certificate
        // retention alone changes them. Historical replay above has already
        // authenticated the original inputs. Compare every other run field,
        // including the whole-snapshot population and policy evidence; never
        // replace the returned current run's own commitments with old ones.
        let mut normalized = current.clone();
        normalized.coordinate.known_at = original.coordinate.known_at;
        normalized.inputs_digest = original.inputs_digest;
        normalized.findings_digest = original.findings_digest;
        let unchanged = normalized == original;
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(if unchanged {
            ProcedureCertificateStatus::Current { checked_at }
        } else {
            ProcedureCertificateStatus::Changed {
                checked_at,
                current: Box::new(current),
            }
        }))
    }

    /// Compute and certify a catalog procedure without publishing any record.
    /// Canonical bytes can be saved by the host and replayed after restarting.
    pub fn certify_procedure(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &ProcedureRequest,
    ) -> Outcome<CertifiedProcedure> {
        let bank_procedure = request.procedure == bank::PROCEDURE;
        if let Err(r) = authorize(self, cx, principal, capability, true, bank_procedure)? {
            return Ok(Err(r));
        }
        let built = match request.build() {
            Ok(p) => p,
            Err(e) => return Ok(Err(lantern_error(e))),
        };
        let row = fa_lantern::bind_version(built.id(), built.version())?;
        if !supported(&row.id, row.version)
            && !extended::supported(&row.id, row.version)
            && !bank::supported(&row.id, row.version)
        {
            return Ok(Err(invalid(
                "this procedure version has no complete registered native certificate closure; ordinary procedure execution is unchanged",
            )));
        }
        for (name, present) in [
            ("account", request.inputs.account.is_some()),
            ("source", request.inputs.source.is_some()),
        ] {
            if present != row.inputs.iter().any(|i| i.name == name) {
                return Ok(Err(invalid(
                    "procedure handles must exactly match its declared inputs",
                )));
            }
        }
        let result = self.query(cx, |db, book| {
            let source = match crate::certificate::certify_report(
                db,
                cx,
                book,
                ReportSelection::OpenItems { account: None },
                request.known_at,
            )? {
                Ok(s) => s.certificate,
                Err(r) => return Ok(Err(r)),
            };
            let (_, approvals) = db
                .execute_certified(
                    &cx.query(),
                    &approval_statement(source.known_at),
                    &GqlParameters::new(),
                    book.symbols.clone(),
                    policy(),
                )
                .map_err(BookError::CertifiedRead)?;
            let extended_inputs = if bank_procedure {
                bank::capture(db, cx, book, source.known_at)?
            } else if extended::supported(&row.id, row.version) {
                extended::capture(db, cx, book, source.known_at)?
            } else {
                Vec::new()
            };
            let mut snapshot = Snapshot::read(
                db,
                &cx.query(),
                book,
                Some(source.known_at),
                request.effective_through,
            )?;
            if bank_procedure
                && let Err(r) = bank::populate(db, cx, book, capability, &mut snapshot)?
            {
                return Ok(Err(r));
            }
            if extended::supported(&row.id, row.version)
                && let Err(r) = extended::unchanged_attestations(db, cx, &snapshot)?
            {
                return Ok(Err(r));
            }
            if let Err(r) = unchanged_approvals(db, &snapshot)? {
                return Ok(Err(r));
            }
            let report = fa_lantern::run_over_metered(
                &snapshot,
                book,
                built.as_ref(),
                request.budget,
                Some(&cx.query()),
            )?;
            let output = match encode_run(&report) {
                Ok(b) => b,
                Err(r) => return Ok(Err(r)),
            };
            let registry = match registry_digest_for_run(&report.procedure, report.version) {
                Ok(closure) => closure,
                Err(r) => return Ok(Err(r)),
            };
            let mut certificate = ProcedureCertificate {
                source,
                approvals,
                extended_inputs,
                registry,
                producer: principal,
                capability_commitment: capability
                    .commitment()
                    .map_err(|e| BookError::Kernel(KernelError::Corrupt(e.to_string())))?,
                report: report.clone(),
                output,
                digest: [0; 32],
            };
            let body = match certificate.body() {
                Ok(b) => b,
                Err(r) => return Ok(Err(r)),
            };
            certificate.digest = domain_digest(CERTIFICATE_DOMAIN, &[&body]);
            Ok(Ok(CertifiedProcedure {
                report,
                certificate,
            }))
        })?;
        if let Err(r) = authorize(self, cx, principal, capability, true, bank_procedure)? {
            return Ok(Err(r));
        }
        Ok(result)
    }

    /// Replay the fixed native inputs, the extra approval closure and the exact
    /// algorithm/output. A later legitimate post cannot move the saved basis.
    pub fn replay_procedure(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &ProcedureCertificate,
    ) -> Outcome<ProcedureRun> {
        let bank_procedure = certificate.report.procedure == bank::PROCEDURE;
        if let Err(r) = authorize(self, cx, principal, capability, false, bank_procedure)? {
            return Ok(Err(r));
        }
        if certificate.book_id() != self.context().book_id {
            return Ok(Err(invalid(
                "procedure certificate belongs to another book",
            )));
        }
        if let Err(r) = certificate.canonical_bytes() {
            return Ok(Err(r));
        }
        let request = match certificate.request() {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let built = request.build()?;
        let result = self.query(cx, |db, book| {
            if let Err(r) = crate::certificate::replay_report(db, cx, book, &certificate.source)? {
                return Ok(Err(r));
            }
            if let Err(e) = db.replay(
                &cx.query(),
                &certificate.approvals,
                &GqlParameters::new(),
                book.symbols.clone(),
                policy(),
            ) {
                return Ok(Err(invalid(format!(
                    "native approval read does not replay: {e}"
                ))));
            }
            if let Err(r) = extended::replay(db, cx, book, certificate)? {
                return Ok(Err(r));
            }
            let mut snapshot = Snapshot::read(
                db,
                &cx.query(),
                book,
                Some(certificate.known_at()),
                request.effective_through,
            )?;
            if bank_procedure
                && let Err(r) = bank::populate(db, cx, book, capability, &mut snapshot)?
            {
                return Ok(Err(r));
            }
            if extended::supported(&certificate.report.procedure, certificate.report.version)
                && let Err(r) = extended::unchanged_attestations(db, cx, &snapshot)?
            {
                return Ok(Err(r));
            }
            if let Err(r) = unchanged_approvals(db, &snapshot)? {
                return Ok(Err(r));
            }
            // A replay re-executes the certified run under the caller's
            // cancellation; its work is the certificate's, never budgeted.
            let report = match fa_lantern::run_over_metered(
                &snapshot,
                book,
                built.as_ref(),
                None,
                Some(&cx.query()),
            ) {
                Ok(report) => report,
                // These parameters and role requirements came from the
                // retained artifact, not a new request. A domain violation
                // is a verification failure even when checked only in run().
                Err(
                    error @ (fa_lantern::LanternError::Parameter { .. }
                    | fa_lantern::LanternError::RoleUnassigned { .. }),
                ) => {
                    return Ok(Err(lantern_error(error)));
                }
                Err(error) => return Err(error.into()),
            };
            let actual = match encode_run(&report) {
                Ok(b) => b,
                Err(r) => return Ok(Err(r)),
            };
            if actual != certificate.output {
                return Ok(Err(invalid(
                    "procedure output, decision card or work transcript does not replay exactly",
                )));
            }
            Ok(Ok(report))
        })?;
        if let Err(r) = authorize(self, cx, principal, capability, false, bank_procedure)? {
            return Ok(Err(r));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
