//! Litigation production volumes (plan §13.2; bead fa-6l9).
//!
//! A production is two acts, sequenced by [`Book::produce_volume`] after it
//! has judged every document's read and every privilege claim: [`Book::produce`]
//! journals the Bates assignment (the kernel's `ProductionControl` Produce
//! record, fa-journal `production`), and [`Book::production_volume`] renders
//! what a volume delivers for those ranges, under the producing capability's
//! own reads:
//!
//! - the Concordance DAT and Opticon OPT load files (fa-formats `load_file`:
//!   `concordance_dat_v1`, `opticon_opt_v1`), one record per produced
//!   document in production order;
//! - each document's native bytes at `NATIVES/<BEGBATES><ext>`, when the
//!   capability reads them in full. A document the capability reads only
//!   through its redacted view (plan §9.6) is listed with `REDACTED` and its
//!   contract and ships no bytes;
//! - the privilege log (fa-notary `PrivilegeLog`): one row for each produced
//!   document whose redacted view withholds at least one chunk, and one for
//!   each document withheld in full, with the claim's date, author,
//!   recipients, description and basis. A withheld document is never
//!   produced and burns no Bates number; it must carry its metadata. A row
//!   without metadata states no date (`UNSPECIFIED`).
//!
//! The volume is a pure function of the journaled ranges, the documents'
//! verified bytes and the claims: rendering it again yields the same files.
//! No-claim boundary: EDRM XML and the `.fab` bundle with its FRE
//! 902(13)/(14) package belong to a production bundle and are not in this
//! build (a profile with an EDRM load-file format is refused here). A
//! privilege log row records the producer's claim; it does not establish the
//! privilege.

use std::collections::{BTreeMap, BTreeSet};

use fa_formats::load_file::{
    self, BatesRange as LoadFileBates, ConfidentialityDesignation, LoadFileRecord,
};
use fa_journal::refusal::{KernelError, Refusal, code, exit};
use fa_journal::{
    Capability, DocumentRead, Produced, ProducedDocument, ProductionProfile, ViewChunk,
};
use fa_model::Oid;
use fa_notary::production::{PrivilegeLog, PrivilegeLogRow, PrivilegeTreatment};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::redaction_contracts::RedactionContracts;
use fa_time::DateDay;

use crate::{Book, BookError, Outcome};

/// The default Opticon volume label.
pub const DEFAULT_VOLUME: &str = "VOL001";

/// One privilege claim's metadata (plan §13.2: date, author, recipients,
/// description, basis).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivilegeEntry {
    pub date: DateDay,
    pub author: String,
    pub recipients: Vec<String>,
    pub description: String,
    pub basis: String,
}

/// The privilege claims a production carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivilegeClaims {
    /// Documents withheld in full: held by the book, never produced, each
    /// with an entry in `metadata`.
    pub withheld: Vec<Oid>,
    /// Keyed by document: a withheld document, or a produced document the
    /// capability reads only through a redacted view that withholds bytes.
    pub metadata: BTreeMap<Oid, PrivilegeEntry>,
}

/// What one production volume delivers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionVolume {
    pub matter: String,
    pub volume: String,
    /// One record per produced document, in production order.
    pub records: Vec<LoadFileRecord>,
    /// The Concordance load file (`concordance_dat_v1`).
    pub dat: String,
    /// The Opticon page cross-reference (`opticon_opt_v1`).
    pub opt: String,
    /// `(native_path, bytes)` for every document read in full, in record
    /// order.
    pub natives: Vec<(String, Vec<u8>)>,
    /// Rows by document oid.
    pub privilege_log: PrivilegeLog,
}

/// The file extension a native keeps, from its registered media type.
fn extension(mime: &str) -> &'static str {
    match mime {
        "application/pdf" => ".pdf",
        "text/plain" => ".txt",
        "text/csv" => ".csv",
        "text/html" => ".html",
        "application/json" => ".json",
        "application/xml" | "text/xml" => ".xml",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/tiff" => ".tif",
        _ => ".bin",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn format_failure(e: fa_formats::FormatError) -> BookError {
    BookError::Kernel(KernelError::Corrupt(format!("production load file: {e}")))
}

/// What a volume can deliver in this build, judged before any read: a
/// Concordance DAT/OPT profile and a valid Opticon volume label.
fn volume_admissible(profile: &ProductionProfile, volume: &str) -> Result<(), Refusal> {
    if profile.load_file_format != 1 {
        return Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "matter `{}` delivers EDRM XML (load-file format {}), which needs the production bundle; this build writes Concordance DAT/OPT only",
                profile.matter, profile.load_file_format
            ),
            "plan §13.2 (load-file export: DAT/OPT or EDRM XML); bead fa-6l9 (EDRM rides the bundle slice)",
            "open the matter with `fa production open <matter> --bates-prefix <PREFIX> --load-file dat`",
        ));
    }
    if volume.is_empty()
        || volume.len() > 64
        || !volume
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!("`{volume}` is not an Opticon volume label"),
            "opticon_opt_v1 (a volume label names the delivery: no commas or line breaks)",
            "pass --volume with 1..=64 ASCII letters, digits, '-', '_' or '.', for example VOL001",
        ));
    }
    Ok(())
}

fn claim_refusal(message: String) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §13.2 (a privilege log lists withheld and redacted documents with date, author, recipients, description and basis)",
        "withhold a document with --withhold <oid> and state its claim in --privilege <file.json>: [{\"document\": <oid>, \"date\": \"YYYY-MM-DD\", \"author\": ..., \"recipients\": [...], \"description\": ..., \"basis\": ...}]; claims name only withheld or redacted documents",
    )
}

/// The claims hold together: every withheld document is one the book holds,
/// is not also produced and states its claim; every claim names a withheld
/// document or a produced one delivered only redacted; every claim names its
/// author, description and basis.
fn check_claims(
    claims: &PrivilegeClaims,
    held: &BTreeSet<Oid>,
    produced: &BTreeSet<Oid>,
    redacted: &BTreeSet<Oid>,
) -> Result<(), Refusal> {
    let withheld: BTreeSet<Oid> = claims.withheld.iter().copied().collect();
    if withheld.len() != claims.withheld.len() {
        return Err(claim_refusal(
            "a production withholds each document once".into(),
        ));
    }
    for oid in &withheld {
        if !held.contains(oid) {
            return Err(Refusal::new(
                code::EVIDENCE_UNKNOWN,
                exit::REFUSAL,
                format!("withheld document {} is not in this book", hex(&oid.0)),
                "plan §13.2 (a privilege log names documents the book holds)",
                "name the oid `fa document list --json` prints for the withheld document",
            ));
        }
        if produced.contains(oid) {
            return Err(claim_refusal(format!(
                "document {} is both produced and withheld",
                hex(&oid.0)
            )));
        }
        if !claims.metadata.contains_key(oid) {
            return Err(claim_refusal(format!(
                "withheld document {} has no privilege claim",
                hex(&oid.0)
            )));
        }
    }
    for (oid, entry) in &claims.metadata {
        if !withheld.contains(oid) && !redacted.contains(oid) {
            return Err(claim_refusal(format!(
                "the privilege claim for {} names a document this production neither withholds nor delivers redacted",
                hex(&oid.0)
            )));
        }
        if entry.author.trim().is_empty()
            || entry.description.trim().is_empty()
            || entry.basis.trim().is_empty()
        {
            return Err(claim_refusal(format!(
                "the privilege claim for {} needs an author, a description and a basis",
                hex(&oid.0)
            )));
        }
    }
    Ok(())
}

/// The number of chunks a redacted view withholds.
fn withheld_chunks(read: &DocumentRead) -> usize {
    match read {
        DocumentRead::Full(_) => 0,
        DocumentRead::Redacted(view) => view
            .chunks
            .iter()
            .filter(|c| matches!(c, ViewChunk::Withheld(_)))
            .count(),
    }
}

impl Book {
    fn held_documents(&self) -> Outcome<BTreeMap<Oid, fa_journal::evidence::DocumentSummary>> {
        Ok(self
            .documents(None)?
            .map(|rows| rows.into_iter().map(|s| (s.oid, s)).collect()))
    }

    /// Produce `documents` in `matter` and render the volume (plan §13.2):
    /// the `produce` op, the matter's profile, the volume, every document's
    /// read under `capability` and every privilege claim are judged before
    /// the Bates assignment is journaled, so a production that could not be
    /// delivered burns no number. Then [`Book::produce`] journals the
    /// assignment and [`Book::production_volume`] renders it.
    #[allow(clippy::too_many_arguments)]
    pub fn produce_volume(
        &mut self,
        capability: &Capability,
        matter: &str,
        documents: Vec<ProducedDocument>,
        claims: &PrivilegeClaims,
        volume: &str,
        effective_date: DateDay,
        idempotency_key: &[u8],
    ) -> Outcome<(Produced, ProductionVolume)> {
        if let Err(denial) = fa_policy::require(capability, fa_policy::Op::Produce, "produce") {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let Some(view) = self.production(matter)? else {
            return Ok(Err(Refusal::new(
                code::PRODUCTION_UNKNOWN,
                exit::REFUSAL,
                format!("this book has no production profile for matter `{matter}`"),
                "plan §13.2 (a ProductionProfile governs a matter's productions)",
                "list the book's matters with `fa production list --json`, or open one with `fa production open <matter> --bates-prefix <PREFIX>`",
            )));
        };
        if let Err(refusal) = volume_admissible(&view.profile, volume) {
            return Ok(Err(refusal));
        }
        let mut redacted = BTreeSet::new();
        for d in &documents {
            match self.read_document_for(capability, &d.document)? {
                Err(refusal) => return Ok(Err(refusal)),
                Ok(read) if withheld_chunks(&read) > 0 => {
                    redacted.insert(d.document);
                }
                Ok(_) => {}
            }
        }
        let held = match self.held_documents()? {
            Ok(held) => held.into_keys().collect(),
            Err(refusal) => return Ok(Err(refusal)),
        };
        let named = documents.iter().map(|d| d.document).collect();
        if let Err(refusal) = check_claims(claims, &held, &named, &redacted) {
            return Ok(Err(refusal));
        }
        let produced = match self.produce(
            capability.clone(),
            matter,
            documents,
            effective_date,
            idempotency_key,
        )? {
            Ok(produced) => produced,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(self
            .production_volume(capability, &produced, claims, volume)?
            .map(|rendered| (produced, rendered)))
    }

    /// Render the production volume of `produced` (the outcome of
    /// [`Book::produce`] or its recorded retry) under `capability`'s reads,
    /// with `claims` in its privilege log. Refused when the matter's
    /// load-file format needs EDRM XML, when `volume` is not a valid Opticon
    /// volume label, and when the claims do not hold together.
    pub fn production_volume(
        &mut self,
        capability: &Capability,
        produced: &Produced,
        claims: &PrivilegeClaims,
        volume: &str,
    ) -> Outcome<ProductionVolume> {
        let profile = &produced.profile;
        if let Err(refusal) = volume_admissible(profile, volume) {
            return Ok(Err(refusal));
        }
        let policy = EvidencePolicy::embedded()?;
        let contracts = RedactionContracts::embedded()?;
        let summaries = match self.held_documents()? {
            Ok(held) => held,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut records = Vec::with_capacity(produced.ranges.len());
        let mut natives = Vec::new();
        let mut rows = Vec::new();
        let mut redacted = BTreeSet::new();
        for produced_range in &produced.ranges {
            let range = &produced_range.range;
            let Some(summary) = summaries.get(&range.document) else {
                return Err(BookError::Kernel(KernelError::Corrupt(format!(
                    "produced document {} is not in the book's document list",
                    hex(&range.document.0)
                ))));
            };
            if summary.doc_commit != range.doc_commit {
                return Err(BookError::Kernel(KernelError::Corrupt(format!(
                    "produced document {} no longer has the commitment its Bates range names",
                    hex(&range.document.0)
                ))));
            }
            let bates = LoadFileBates::new(
                profile.matter.clone(),
                profile.bates_prefix.clone(),
                range.start,
                range.pages(),
            )
            .map_err(format_failure)?;
            let beg = bates.beg_bates();
            let read = match self.read_document_for(capability, &range.document)? {
                Err(refusal) => return Ok(Err(refusal)),
                Ok(read) => read,
            };
            let withheld = withheld_chunks(&read);
            let (native_path, redaction_contract) = match read {
                DocumentRead::Full(doc) => {
                    let path = format!("NATIVES/{beg}{}", extension(&summary.mime));
                    natives.push((path.clone(), doc.bytes));
                    (path, None)
                }
                DocumentRead::Redacted(view) => {
                    if withheld > 0 {
                        redacted.insert(range.document);
                        let claim = claims.metadata.get(&range.document);
                        rows.push(PrivilegeLogRow {
                            document_oid: range.document,
                            doc_commit: range.doc_commit,
                            bates_range: Some(format!("{}..={}", beg, bates.end_bates())),
                            date: claim.map(|c| c.date),
                            author: claim
                                .map_or_else(|| "UNSPECIFIED".to_string(), |c| c.author.clone()),
                            recipients: claim.map_or_else(Vec::new, |c| c.recipients.clone()),
                            description: claim.map_or_else(
                                || {
                                    format!(
                                        "Document governed by redaction contract {}",
                                        view.contract
                                    )
                                },
                                |c| c.description.clone(),
                            ),
                            basis: claim.map_or_else(
                                || format!("Redaction contract {}", view.contract),
                                |c| c.basis.clone(),
                            ),
                            treatment: PrivilegeTreatment::RedactedInPart {
                                contract_id: view.contract,
                                withheld_chunks: withheld,
                                total_chunks: view.chunks.len(),
                            },
                        });
                    }
                    let contract = contracts
                        .get(view.contract)
                        .map_or_else(|| view.contract.to_string(), |c| c.name.clone());
                    (String::new(), Some(contract))
                }
            };
            let designation =
                ConfidentialityDesignation::from_tag(range.designation).ok_or_else(|| {
                    BookError::Kernel(KernelError::Corrupt(format!(
                        "Bates range designation {} is not registered",
                        range.designation
                    )))
                })?;
            let document_kind = policy
                .kind_by_tag(summary.kind)
                .map_or_else(|| summary.kind.to_string(), |k| k.name.clone());
            records.push(LoadFileRecord {
                doc_id: beg,
                document_oid_hex: hex(&range.document.0),
                doc_commit_hex: hex(&range.doc_commit),
                bates,
                designation,
                document_kind,
                mime_type: summary.mime.clone(),
                byte_length: summary.size,
                redacted: redaction_contract.is_some(),
                redaction_contract,
                exhibit_labels: Vec::new(),
                text_path: String::new(),
                native_path,
            });
        }
        let held = summaries.keys().copied().collect();
        let named = produced.ranges.iter().map(|r| r.range.document).collect();
        if let Err(refusal) = check_claims(claims, &held, &named, &redacted) {
            return Ok(Err(refusal));
        }
        for oid in &claims.withheld {
            let (Some(summary), Some(claim)) = (summaries.get(oid), claims.metadata.get(oid))
            else {
                continue;
            };
            rows.push(PrivilegeLogRow {
                document_oid: *oid,
                doc_commit: summary.doc_commit,
                bates_range: None,
                date: Some(claim.date),
                author: claim.author.clone(),
                recipients: claim.recipients.clone(),
                description: claim.description.clone(),
                basis: claim.basis.clone(),
                treatment: PrivilegeTreatment::WithheldInFull,
            });
        }
        rows.sort_by_key(|r| r.document_oid);
        let dat = load_file::write_concordance_dat(&records).map_err(format_failure)?;
        let opt = load_file::write_opticon_opt(volume, &records).map_err(format_failure)?;
        Ok(Ok(ProductionVolume {
            matter: profile.matter.clone(),
            volume: volume.to_string(),
            records,
            dat,
            opt,
            natives,
            privilege_log: PrivilegeLog {
                matter_id: profile.matter.clone(),
                rows,
            },
        }))
    }
}
