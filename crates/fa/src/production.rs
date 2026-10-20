//! Litigation production volumes (plan §13.2; bead fa-6l9).
//!
//! A production is two acts, sequenced by [`Book::produce_volume`] after it
//! has judged every document's read: [`Book::produce`] journals the Bates
//! assignment (the kernel's `ProductionControl` Produce record, fa-journal
//! `production`), and [`Book::production_volume`] renders what a volume
//! delivers for those ranges, under the producing capability's own reads:
//!
//! - the Concordance DAT and Opticon OPT load files (fa-formats `load_file`:
//!   `concordance_dat_v1`, `opticon_opt_v1`), one record per produced
//!   document in production order;
//! - each document's native bytes at `NATIVES/<BEGBATES><ext>`, when the
//!   capability reads them in full. A document the capability reads only
//!   through its redacted view (plan §9.6) is listed with `REDACTED` and its
//!   contract and ships no bytes.
//!
//! The volume is a pure function of the journaled ranges and the documents'
//! verified bytes: rendering it again yields the same files. No-claim
//! boundary: EDRM XML, the privilege log, and the `.fab` bundle with its
//! FRE 902(13)/(14) package belong to a production bundle and are not in this
//! build (a profile with an EDRM load-file format is refused here).

use std::collections::BTreeMap;

use fa_formats::load_file::{
    self, BatesRange as LoadFileBates, ConfidentialityDesignation, LoadFileRecord,
};
use fa_journal::refusal::{KernelError, Refusal, code, exit};
use fa_journal::{Capability, DocumentRead, Produced, ProducedDocument, ProductionProfile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::redaction_contracts::RedactionContracts;
use fa_time::DateDay;

use crate::{Book, BookError, Outcome};

/// The default Opticon volume label.
pub const DEFAULT_VOLUME: &str = "VOL001";

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

impl Book {
    /// Produce `documents` in `matter` and render the volume (plan §13.2):
    /// the `produce` op, the matter's profile, the volume and every
    /// document's read under `capability` are judged before the Bates
    /// assignment is journaled, so a production that could not be delivered
    /// burns no number. Then [`Book::produce`] journals the assignment and
    /// [`Book::production_volume`] renders it.
    pub fn produce_volume(
        &mut self,
        capability: &Capability,
        matter: &str,
        documents: Vec<ProducedDocument>,
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
        for d in &documents {
            if let Err(refusal) = self.read_document_for(capability, &d.document)? {
                return Ok(Err(refusal));
            }
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
            .production_volume(capability, &produced, volume)?
            .map(|rendered| (produced, rendered)))
    }

    /// Render the production volume of `produced` (the outcome of
    /// [`Book::produce`] or its recorded retry) under `capability`'s reads.
    /// Refused when the matter's load-file format needs EDRM XML, and when
    /// `volume` is not a valid Opticon volume label.
    pub fn production_volume(
        &mut self,
        capability: &Capability,
        produced: &Produced,
        volume: &str,
    ) -> Outcome<ProductionVolume> {
        let profile = &produced.profile;
        if let Err(refusal) = volume_admissible(profile, volume) {
            return Ok(Err(refusal));
        }
        let policy = EvidencePolicy::embedded()?;
        let contracts = RedactionContracts::embedded()?;
        let summaries: BTreeMap<_, _> = match self.documents(None)? {
            Ok(rows) => rows.into_iter().map(|s| (s.oid, s)).collect(),
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut records = Vec::with_capacity(produced.ranges.len());
        let mut natives = Vec::new();
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
            let (native_path, redacted, redaction_contract) =
                match self.read_document_for(capability, &range.document)? {
                    Err(refusal) => return Ok(Err(refusal)),
                    Ok(DocumentRead::Full(doc)) => {
                        let path = format!("NATIVES/{beg}{}", extension(&summary.mime));
                        natives.push((path.clone(), doc.bytes));
                        (path, false, None)
                    }
                    Ok(DocumentRead::Redacted(view)) => {
                        let contract = contracts
                            .get(view.contract)
                            .map_or_else(|| view.contract.to_string(), |c| c.name.clone());
                        (String::new(), true, Some(contract))
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
                redacted,
                redaction_contract,
                exhibit_labels: Vec::new(),
                text_path: String::new(),
                native_path,
            });
        }
        let dat = load_file::write_concordance_dat(&records).map_err(format_failure)?;
        let opt = load_file::write_opticon_opt(volume, &records).map_err(format_failure)?;
        Ok(Ok(ProductionVolume {
            matter: profile.matter.clone(),
            volume: volume.to_string(),
            records,
            dat,
            opt,
            natives,
        }))
    }
}
