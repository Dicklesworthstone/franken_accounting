//! Litigation production tooling: `ProductionProfile`, multi-matter Bates
//! assignment, `ExhibitMark`, privilege logs, and FRE 902(13)/(14) technical
//! certification packages (plan §11.8, §13.2–§13.4, Appendix A; bead `fa-6l9`).
//!
//! All litigation production metadata lives outside the immutable `Document`
//! payload so `doc_commit` never changes when a document is Bates-stamped,
//! designated under a protective order, or marked as an exhibit in one or more
//! matters.

use std::collections::BTreeMap;

use fa_journal::{DocumentRead, KernelError, RedactedView};
use fa_model::{DecodeError, EncodeError, Oid, Reader, Writer};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::bundle::{Bundle, ProductionReceipt};
use crate::state::StoredCheckpoint;

pub const PRODUCTION_PROFILE_DOMAIN: &[u8] = b"fa:production-profile:v1";
pub const EXHIBIT_MARK_DOMAIN: &[u8] = b"fa:exhibit-mark:v1";
pub const PRIVILEGE_LOG_DOMAIN: &[u8] = b"fa:privilege-log:v1";
pub const MAX_BATES_PREFIX_BYTES: usize = 16;
pub const MAX_MATTER_ID_BYTES: usize = 128;
pub const MAX_EXHIBIT_LABEL_BYTES: usize = 64;

fn hash_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Confidentiality designation under a matter's protective order (Appendix A `ProductionProfile`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidentialityDesignation {
    None = 0,
    Confidential = 1,
    AttorneysEyesOnly = 2,
    HighlyConfidential = 3,
}

impl ConfidentialityDesignation {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::None),
            1 => Some(Self::Confidential),
            2 => Some(Self::AttorneysEyesOnly),
            3 => Some(Self::HighlyConfidential),
            _ => None,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Confidential => "CONFIDENTIAL",
            Self::AttorneysEyesOnly => "ATTORNEYS' EYES ONLY",
            Self::HighlyConfidential => "HIGHLY CONFIDENTIAL",
        }
    }
}

/// Load-file format selector on a [`ProductionProfile`] (Appendix A `load_file_format: u8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadFileFormat {
    ConcordanceDatOpt = 1,
    EdrmXml = 2,
    Both = 3,
}

impl LoadFileFormat {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::ConcordanceDatOpt),
            2 => Some(Self::EdrmXml),
            3 => Some(Self::Both),
            _ => None,
        }
    }
}

/// Errors returned when validating or encoding litigation production metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProductionError {
    InvalidField(&'static str),
    BatesOverflow,
    Encode(EncodeError),
    Decode(DecodeError),
}

impl core::fmt::Display for ProductionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid production field: {field}"),
            Self::BatesOverflow => write!(f, "Bates number overflow"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for ProductionError {}

impl From<EncodeError> for ProductionError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl From<DecodeError> for ProductionError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// Matter-scoped production profile (Appendix A `ProductionProfile`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionProfile {
    pub matter_id: String,
    /// Prefix for Bates stamps in this matter (1..=16 ASCII bytes, e.g. `"ACME-SEC"`).
    pub bates_prefix: String,
    /// Next starting Bates number (>= 1).
    pub next_bates: u64,
    /// Per-document confidentiality designation (`0..=3`).
    pub designations: BTreeMap<Oid, ConfidentialityDesignation>,
    /// Optional governing protective order document OID.
    pub protective_order_oid: Option<Oid>,
    /// Selected discovery load-file format (`1..=3`).
    pub load_file_format: LoadFileFormat,
}

impl ProductionProfile {
    pub fn new(
        matter_id: impl Into<String>,
        bates_prefix: impl Into<String>,
        next_bates: u64,
        load_file_format: LoadFileFormat,
    ) -> Result<Self, ProductionError> {
        let profile = Self {
            matter_id: matter_id.into(),
            bates_prefix: bates_prefix.into(),
            next_bates,
            designations: BTreeMap::new(),
            protective_order_oid: None,
            load_file_format,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), ProductionError> {
        if self.matter_id.trim().is_empty() || self.matter_id.len() > MAX_MATTER_ID_BYTES {
            return Err(ProductionError::InvalidField("matter_id"));
        }
        if self.bates_prefix.trim().is_empty()
            || self.bates_prefix.len() > MAX_BATES_PREFIX_BYTES
            || !self.bates_prefix.is_ascii()
        {
            return Err(ProductionError::InvalidField("bates_prefix"));
        }
        if self.next_bates == 0 {
            return Err(ProductionError::InvalidField("next_bates"));
        }
        Ok(())
    }

    #[must_use]
    pub fn designation_for(&self, oid: &Oid) -> ConfidentialityDesignation {
        self.designations
            .get(oid)
            .copied()
            .unwrap_or(ConfidentialityDesignation::None)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionError> {
        self.validate()?;
        let mut w = Writer::with_capacity(128 + self.designations.len() * 36);
        w.bytes(PRODUCTION_PROFILE_DOMAIN)
            .str(&self.matter_id)
            .str(&self.bates_prefix)
            .u64(self.next_bates);
        let pairs: Vec<(&Oid, &ConfidentialityDesignation)> = self.designations.iter().collect();
        w.list(&pairs, |w, (oid, des)| {
            w.fixed(&oid.0).u8(des.tag());
        });
        w.opt(self.protective_order_oid.as_ref(), |w, oid| {
            w.fixed(&oid.0);
        });
        w.u8(self.load_file_format.tag());
        Ok(w.finish()?)
    }

    pub fn oid(&self) -> Result<Oid, ProductionError> {
        let bytes = self.canonical_bytes()?;
        Ok(Oid(hash_domain(PRODUCTION_PROFILE_DOMAIN, &bytes)))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionError> {
        let mut r = Reader::new(bytes);
        if r.bytes(64, "profile.domain")? != PRODUCTION_PROFILE_DOMAIN {
            return Err(ProductionError::Decode(r.invalid("profile.domain")));
        }
        let matter_id = r.str(MAX_MATTER_ID_BYTES, "profile.matter_id")?.to_string();
        let bates_prefix = r
            .str(MAX_BATES_PREFIX_BYTES, "profile.bates_prefix")?
            .to_string();
        let next_bates = r.u64("profile.next_bates")?;
        let raw_pairs = r.list(65_536, "profile.designations", |r| {
            let oid = Oid(r.fixed("profile.designation.oid")?);
            let tag = r.u8("profile.designation.tag")?;
            let Some(des) = ConfidentialityDesignation::from_tag(tag) else {
                return Err(r.invalid("profile.designation.tag"));
            };
            Ok((oid, des))
        })?;
        let mut designations = BTreeMap::new();
        for (oid, des) in raw_pairs {
            if designations.insert(oid, des).is_some() {
                return Err(ProductionError::InvalidField("duplicate designation oid"));
            }
        }
        let protective_order_oid = r.opt("profile.protective_order_oid", |r| {
            Ok(Oid(r.fixed("profile.protective_order_oid")?))
        })?;
        let fmt_tag = r.u8("profile.load_file_format")?;
        let Some(load_file_format) = LoadFileFormat::from_tag(fmt_tag) else {
            return Err(ProductionError::Decode(
                r.invalid("profile.load_file_format"),
            ));
        };
        r.finish()?;
        let profile = Self {
            matter_id,
            bates_prefix,
            next_bates,
            designations,
            protective_order_oid,
            load_file_format,
        };
        profile.validate()?;
        Ok(profile)
    }
}

/// Contiguous Bates number range assigned to a document in a specific matter (plan §13.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatesAssignment {
    pub document_oid: Oid,
    pub doc_commit: [u8; 32],
    pub matter_id: String,
    pub bates_prefix: String,
    pub start_number: u64,
    pub end_number: u64,
    pub page_count: u64,
    pub designation: ConfidentialityDesignation,
}

impl BatesAssignment {
    #[must_use]
    pub fn beg_bates(&self) -> String {
        format!("{}-{:08}", self.bates_prefix, self.start_number)
    }

    #[must_use]
    pub fn end_bates(&self) -> String {
        format!("{}-{:08}", self.bates_prefix, self.end_number)
    }

    #[must_use]
    pub fn range_label(&self) -> String {
        format!("{}..={}", self.beg_bates(), self.end_bates())
    }
}

/// Exhibit mark binding a trial/deposition exhibit label to a subject OID and
/// signed digest in a specific matter (Appendix A `ExhibitMark`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExhibitMark {
    pub subject_oid: Oid,
    pub label: String,
    pub matter_id: String,
    pub principal: VId,
    pub signed_digest: [u8; 32],
}

impl ExhibitMark {
    pub fn new(
        subject_oid: Oid,
        label: impl Into<String>,
        matter_id: impl Into<String>,
        principal: VId,
        signed_digest: [u8; 32],
    ) -> Result<Self, ProductionError> {
        let mark = Self {
            subject_oid,
            label: label.into(),
            matter_id: matter_id.into(),
            principal,
            signed_digest,
        };
        mark.validate()?;
        Ok(mark)
    }

    pub fn validate(&self) -> Result<(), ProductionError> {
        if self.label.trim().is_empty() || self.label.len() > MAX_EXHIBIT_LABEL_BYTES {
            return Err(ProductionError::InvalidField("label"));
        }
        if self.matter_id.trim().is_empty() || self.matter_id.len() > MAX_MATTER_ID_BYTES {
            return Err(ProductionError::InvalidField("matter_id"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionError> {
        self.validate()?;
        let mut w = Writer::with_capacity(160);
        w.bytes(EXHIBIT_MARK_DOMAIN)
            .fixed(&self.subject_oid.0)
            .str(&self.label)
            .str(&self.matter_id)
            .u128(self.principal.0)
            .fixed(&self.signed_digest);
        Ok(w.finish()?)
    }

    pub fn oid(&self) -> Result<Oid, ProductionError> {
        let bytes = self.canonical_bytes()?;
        Ok(Oid(hash_domain(EXHIBIT_MARK_DOMAIN, &bytes)))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionError> {
        let mut r = Reader::new(bytes);
        if r.bytes(64, "exhibit.domain")? != EXHIBIT_MARK_DOMAIN {
            return Err(ProductionError::Decode(r.invalid("exhibit.domain")));
        }
        let subject_oid = Oid(r.fixed("exhibit.subject_oid")?);
        let label = r.str(MAX_EXHIBIT_LABEL_BYTES, "exhibit.label")?.to_string();
        let matter_id = r.str(MAX_MATTER_ID_BYTES, "exhibit.matter_id")?.to_string();
        let principal = VId(r.u128("exhibit.principal")?);
        let signed_digest = r.fixed("exhibit.signed_digest")?;
        r.finish()?;
        Self::new(subject_oid, label, matter_id, principal, signed_digest)
    }
}

/// Multi-matter production registry that tracks per-matter [`ProductionProfile`]s,
/// idempotent Bates assignments per `(matter_id, document_oid)`, and exhibit marks.
///
/// Producing the same document twice in the same matter returns its existing
/// [`BatesAssignment`] without burning new numbers; producing the same document
/// in a second matter assigns that second matter's Bates range while preserving
/// the first matter's assignment and leaving the document's `doc_commit` untouched.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatterProductionRegistry {
    profiles: BTreeMap<String, ProductionProfile>,
    assignments: BTreeMap<(String, Oid), BatesAssignment>,
    exhibits: Vec<ExhibitMark>,
}

impl MatterProductionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_profile(&mut self, profile: ProductionProfile) -> Result<(), ProductionError> {
        profile.validate()?;
        self.profiles.insert(profile.matter_id.clone(), profile);
        Ok(())
    }

    #[must_use]
    pub fn profile(&self, matter_id: &str) -> Option<&ProductionProfile> {
        self.profiles.get(matter_id)
    }

    /// Assign (or retrieve existing) contiguous Bates numbers for `document_oid`
    /// in `matter_id`.
    pub fn assign_bates(
        &mut self,
        matter_id: &str,
        document_oid: Oid,
        doc_commit: [u8; 32],
        page_count: u64,
    ) -> Result<BatesAssignment, ProductionError> {
        if page_count == 0 {
            return Err(ProductionError::InvalidField("page_count"));
        }
        if let Some(existing) = self.assignments.get(&(matter_id.to_string(), document_oid)) {
            return Ok(existing.clone());
        }
        let Some(profile) = self.profiles.get_mut(matter_id) else {
            return Err(ProductionError::InvalidField("unknown matter_id"));
        };
        let start_number = profile.next_bates;
        let end_number = start_number
            .checked_add(page_count - 1)
            .ok_or(ProductionError::BatesOverflow)?;
        let next_bates = end_number
            .checked_add(1)
            .ok_or(ProductionError::BatesOverflow)?;
        let designation = profile.designation_for(&document_oid);
        let assignment = BatesAssignment {
            document_oid,
            doc_commit,
            matter_id: profile.matter_id.clone(),
            bates_prefix: profile.bates_prefix.clone(),
            start_number,
            end_number,
            page_count,
            designation,
        };
        profile.next_bates = next_bates;
        self.assignments
            .insert((matter_id.to_string(), document_oid), assignment.clone());
        Ok(assignment)
    }

    /// Return all Bates ranges assigned to `document_oid` across all matters,
    /// ordered deterministically by `matter_id`.
    #[must_use]
    pub fn bates_for_document(&self, document_oid: &Oid) -> Vec<BatesAssignment> {
        self.assignments
            .iter()
            .filter_map(|((_, oid), assignment)| {
                if oid == document_oid {
                    Some(assignment.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all Bates assignments in `matter_id`, ordered by `start_number`.
    #[must_use]
    pub fn bates_for_matter(&self, matter_id: &str) -> Vec<BatesAssignment> {
        let mut out: Vec<BatesAssignment> = self
            .assignments
            .iter()
            .filter_map(|((m, _), assignment)| {
                if m == matter_id {
                    Some(assignment.clone())
                } else {
                    None
                }
            })
            .collect();
        out.sort_by_key(|a| a.start_number);
        out
    }

    pub fn mark_exhibit(&mut self, mark: ExhibitMark) -> Result<Oid, ProductionError> {
        let oid = mark.oid()?;
        if !self.exhibits.contains(&mark) {
            self.exhibits.push(mark);
        }
        Ok(oid)
    }

    #[must_use]
    pub fn exhibits_for_subject(&self, matter_id: &str, subject_oid: &Oid) -> Vec<ExhibitMark> {
        self.exhibits
            .iter()
            .filter(|m| m.matter_id == matter_id && &m.subject_oid == subject_oid)
            .cloned()
            .collect()
    }
}

/// How a privileged or protected document was treated in the production (plan §13.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivilegeTreatment {
    /// Document withheld in its entirety; only its public commitment and privilege row are disclosed.
    WithheldInFull,
    /// Document produced via a governed [`RedactedView`]; `withheld_chunks` of `total_chunks` were redacted.
    RedactedInPart {
        contract_id: u16,
        withheld_chunks: usize,
        total_chunks: usize,
    },
}

impl PrivilegeTreatment {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::WithheldInFull => "WITHHELD_IN_FULL".to_string(),
            Self::RedactedInPart {
                contract_id,
                withheld_chunks,
                total_chunks,
            } => format!(
                "REDACTED_IN_PART(contract={contract_id}, withheld_chunks={withheld_chunks}/{total_chunks})"
            ),
        }
    }
}

/// Caller-supplied metadata describing the privilege claim on a redacted or withheld document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivilegeMetadata {
    pub document_oid: Oid,
    pub doc_commit: [u8; 32],
    pub date: DateDay,
    pub author: String,
    pub recipients: Vec<String>,
    pub description: String,
    pub basis: String,
}

/// One row of a matter's privilege log (plan §13.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivilegeLogRow {
    pub document_oid: Oid,
    pub doc_commit: [u8; 32],
    pub bates_range: Option<String>,
    /// The document's date; `None` (rendered `UNSPECIFIED`) when no privilege
    /// metadata states it, never a made-up day.
    pub date: Option<DateDay>,
    pub author: String,
    pub recipients: Vec<String>,
    pub description: String,
    pub basis: String,
    pub treatment: PrivilegeTreatment,
}

/// Deterministic privilege log generated from a matter's redacted views and
/// withheld documents (plan §13.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivilegeLog {
    pub matter_id: String,
    pub rows: Vec<PrivilegeLogRow>,
}

impl PrivilegeLog {
    /// Build a deterministic privilege log for `matter_id` from the documents
    /// observed during bundle production (`reads`), any documents withheld in
    /// full (`withheld_in_full`), the privilege metadata map (`metadata`), and
    /// the matter's [`MatterProductionRegistry`].
    pub fn build(
        matter_id: impl Into<String>,
        reads: &BTreeMap<Oid, DocumentRead>,
        withheld_in_full: &[Oid],
        metadata: &BTreeMap<Oid, PrivilegeMetadata>,
        registry: &MatterProductionRegistry,
    ) -> Result<Self, ProductionError> {
        let matter_id = matter_id.into();
        if matter_id.trim().is_empty() {
            return Err(ProductionError::InvalidField("matter_id"));
        }
        let mut rows = Vec::new();

        for (oid, read) in reads {
            if let DocumentRead::Redacted(view) = read {
                let withheld_chunks = count_withheld_chunks(view);
                if withheld_chunks > 0 {
                    let meta = metadata.get(oid);
                    let bates_range = registry
                        .assignments
                        .get(&(matter_id.clone(), *oid))
                        .map(BatesAssignment::range_label);
                    rows.push(PrivilegeLogRow {
                        document_oid: *oid,
                        doc_commit: view.doc_commit,
                        bates_range,
                        date: meta.map(|m| m.date),
                        author: meta
                            .map_or_else(|| "UNSPECIFIED".to_string(), |m| m.author.clone()),
                        recipients: meta.map_or_else(Vec::new, |m| m.recipients.clone()),
                        description: meta.map_or_else(
                            || format!("Document governed by redaction contract {}", view.contract),
                            |m| m.description.clone(),
                        ),
                        basis: meta.map_or_else(
                            || format!("Redaction contract {}", view.contract),
                            |m| m.basis.clone(),
                        ),
                        treatment: PrivilegeTreatment::RedactedInPart {
                            contract_id: view.contract,
                            withheld_chunks,
                            total_chunks: view.chunks.len(),
                        },
                    });
                }
            }
        }

        let mut sorted_withheld = withheld_in_full.to_vec();
        sorted_withheld.sort();
        sorted_withheld.dedup();
        for oid in sorted_withheld {
            if rows.iter().any(|r| r.document_oid == oid) {
                continue;
            }
            let Some(meta) = metadata.get(&oid) else {
                return Err(ProductionError::InvalidField(
                    "withheld_in_full document missing PrivilegeMetadata",
                ));
            };
            rows.push(PrivilegeLogRow {
                document_oid: oid,
                doc_commit: meta.doc_commit,
                bates_range: None,
                date: Some(meta.date),
                author: meta.author.clone(),
                recipients: meta.recipients.clone(),
                description: meta.description.clone(),
                basis: meta.basis.clone(),
                treatment: PrivilegeTreatment::WithheldInFull,
            });
        }

        rows.sort_by_key(|r| r.document_oid);
        Ok(Self { matter_id, rows })
    }

    /// Render the privilege log as a deterministic Markdown table.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = format!(
            "# Privilege Log — Matter `{}`\n\n\
             | Document OID | BLAKE3 Commitment | Bates Range | Date | Author | Recipients | Basis | Treatment | Description |\n\
             | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n",
            self.matter_id
        );
        for row in &self.rows {
            let bates = row.bates_range.as_deref().unwrap_or("WITHHELD");
            let recipients = row.recipients.join("; ");
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} |\n",
                hex(&row.document_oid.0),
                hex(&row.doc_commit),
                bates,
                row.date
                    .map_or_else(|| "UNSPECIFIED".to_string(), |d| d.to_string()),
                row.author.replace('|', "/"),
                recipients.replace('|', "/"),
                row.basis.replace('|', "/"),
                row.treatment.label(),
                row.description.replace('|', "/"),
            ));
        }
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_domain(PRIVILEGE_LOG_DOMAIN, self.to_markdown().as_bytes())
    }
}

fn count_withheld_chunks(view: &RedactedView) -> usize {
    view.chunks
        .iter()
        .filter(|c| matches!(c, fa_journal::ViewChunk::Withheld(_)))
        .count()
}

/// FRE 902(13) / 902(14) technical self-authentication package (plan §13.4).
///
/// States strictly the technical predicates established by the `.fab` bundle,
/// the signed [`ProductionReceipt`], the [`StoredCheckpoint`], and the
/// standalone `fa-verify` verifier. It never states a legal conclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fre902Package {
    pub matter_id: String,
    pub book_id_hex: String,
    pub branch_id_hex: String,
    pub through_seq: CommitSeq,
    pub leaf_count: u64,
    pub checkpoint_oid_hex: String,
    pub bundle_digest_hex: String,
    pub signer_key_id_hex: String,
    pub signer_public_key_hex: String,
    pub produced_at_seq: CommitSeq,
    pub document_commitments: Vec<(Oid, [u8; 32], Option<String>)>,
    pub declaration_template_md: String,
    pub verification_procedure_md: String,
    pub adverse_party_notice_template_md: String,
}

impl Fre902Package {
    /// Construct the FRE 902(13)/(14) technical certification package for a
    /// produced `.fab` [`Bundle`], its [`StoredCheckpoint`], its signed
    /// [`ProductionReceipt`], the book's Ed25519 `signer_public_key`, and the
    /// matter's [`BatesAssignment`]s.
    #[must_use]
    pub fn generate(
        matter_id: impl Into<String>,
        bundle: &Bundle,
        checkpoint: &StoredCheckpoint,
        receipt: &ProductionReceipt,
        signer_public_key: &[u8; 32],
        assignments: &[BatesAssignment],
    ) -> Self {
        let matter_id = matter_id.into();
        let stmt = &checkpoint.checkpoint.body.statement;
        let book_id_hex = hex(&stmt.book_id.0);
        let branch_id_hex = hex(&stmt.branch_id.0);
        let through_seq = stmt.through_seq;
        let leaf_count = stmt.leaf_count;
        let checkpoint_oid_hex = hex(&checkpoint.oid.0);
        let bundle_digest_hex = hex(&bundle.digest);
        let signer_key_id_hex = hex(&receipt.signer_key_id);
        let signer_public_key_hex = hex(signer_public_key);
        let produced_at_seq = receipt.body.produced_at_seq;

        let mut document_commitments: Vec<(Oid, [u8; 32], Option<String>)> = assignments
            .iter()
            .map(|a| (a.document_oid, a.doc_commit, Some(a.range_label())))
            .collect();
        document_commitments.sort_by_key(|(oid, _, _)| *oid);

        let mut doc_table = String::new();
        if document_commitments.is_empty() {
            doc_table.push_str("| *(none)* | *(none)* | *(none)* |\n");
        } else {
            for (oid, commit, bates) in &document_commitments {
                doc_table.push_str(&format!(
                    "| `{}` | `{}` | {} |\n",
                    hex(&oid.0),
                    hex(commit),
                    bates.as_deref().unwrap_or("UNSTAMPED"),
                ));
            }
        }

        let declaration_template_md = format!(
            "# Technical Declaration for Electronic System Records and Data (FRE 902(13) / 902(14) Template)\n\
             \n\
             > **Notice of Technical Scope (Plan §13.4):** This template states only the cryptographic and\n\
             > computational predicates established by FrankenAccounting (`fa-notary` and `fa-verify`).\n\
             > Mapping these technical predicates to legal admissibility requirements under Federal Rules\n\
             > of Evidence 902(13), 902(14), and 803(6) is reserved to the declarant and legal counsel.\n\
             \n\
             ## 1. Matter and Production Identification\n\
             - **Matter ID:** `{matter_id}`\n\
             - **Book ID:** `{book_id_hex}`\n\
             - **Branch ID:** `{branch_id_hex}`\n\
             - **Accumulator Prefix:** commit sequence `{}` (`{leaf_count}` journal leaves)\n\
             - **Transparency Checkpoint OID:** `{checkpoint_oid_hex}`\n\
             - **Evidence Bundle Digest (`fa:bundle:v1` BLAKE3):** `{bundle_digest_hex}`\n\
             - **Production Admitted at Commit Sequence:** `{}`\n\
             - **Book Signer Key ID:** `{signer_key_id_hex}`\n\
             - **Book Signer Ed25519 Public Key:** `{signer_public_key_hex}`\n\
             \n\
             ## 2. Per-Document BLAKE3 Commitments (`fa:doc:v1`)\n\
             | Document OID | BLAKE3 Commitment (`doc_commit`) | Matter Bates Range |\n\
             | :--- | :--- | :--- |\n\
             {doc_table}\n\
             ## 3. Qualified Person Technical Statement (To Be Completed by Declarant)\n\
             1. I, `[NAME AND TITLE OF QUALIFIED PERSON]`, am familiar with the operation of the FrankenAccounting\n\
                system of record that maintains Book `{book_id_hex}`.\n\
             2. Each journal entry in the produced `.fab` bundle is a leaf of an append-only BLAKE3 Merkle\n\
                Mountain Range (`fa:leaf:v1` / `fa:mmr:node:v1`) whose root at commit sequence `{}` is\n\
                signed by Ed25519 key `{signer_public_key_hex}` in Transparency Checkpoint `{checkpoint_oid_hex}`.\n\
             3. Each cited document is bound at intake by its 256-bit BLAKE3 chunk-tree commitment (`fa:doc:v1`).\n\
                Any single-bit modification to a document, entry, balance proof, or scope index causes\n\
                `fa-verify` to reject the bundle with exit code `8` (`verification`).\n\
             \n\
             I declare under penalty of perjury that the foregoing technical facts are true and correct.\n\
             \n\
             Executed on: `[DATE]`  \n\
             Signature: `____________________________________`  \n\
             Printed Name: `[QUALIFIED PERSON NAME]`\n",
            through_seq.0, produced_at_seq.0, through_seq.0,
        );

        let verification_procedure_md = format!(
            "# Independent Offline Hash-Verification Procedure (`fa-verify`)\n\
             \n\
             Any party or examiner can verify the produced `.fab` bundle and `.far` receipt offline\n\
             using the dependency-free `fa-verify` binary without access to the originating database:\n\
             \n\
             1. **Verify the `.fab` bundle and `.far` production receipt:**\n\
                ```sh\n\
                fa-verify bundle <bundle.fab> \\\n\
                  --key {signer_public_key_hex} \\\n\
                  --receipt <receipt.far> \\\n\
                  --json\n\
                ```\n\
             2. **Expected Technical Predicates Checked by `fa-verify`:**\n\
                - `bundle_digest` equals `{bundle_digest_hex}`.\n\
                - `checkpoint_oid` equals `{checkpoint_oid_hex}`.\n\
                - Ed25519 signature on the `TransparencyCheckpoint` verifies under public key `{signer_public_key_hex}`.\n\
                - Ed25519 signature on the `ProductionReceipt` verifies under public key `{signer_public_key_hex}` and binds `bundle_digest` `{bundle_digest_hex}`.\n\
                - Every in-scope entry payload hashes to its MMR leaf envelope and verifies against the checkpoint root.\n\
                - Every document stub rebuilds its `fa:doc:v1` commitment from `(kind, length, chunk_root)`.\n\
                - Every included balance proof recomputes the exact debit and credit totals from its leaf contributions.\n"
        );

        let adverse_party_notice_template_md = format!(
            "# Notice of Intent to Offer Certified Electronic Records (FRE 902(13) / 902(14) Notice Template)\n\
             \n\
             - **Matter:** `{matter_id}`\n\
             - **Producing Party:** `[PRODUCING PARTY]`\n\
             - **Receiving Party:** `[ADVERSE PARTY / COUNSEL]`\n\
             - **Evidence Bundle Digest (`fa:bundle:v1`):** `{bundle_digest_hex}`\n\
             - **Checkpoint OID:** `{checkpoint_oid_hex}`\n\
             - **Verification Public Key (Ed25519):** `{signer_public_key_hex}`\n\
             \n\
             Please take notice that `[PRODUCING PARTY]` intends to offer the electronic accounting\n\
             records contained in evidence bundle `{bundle_digest_hex}` (and the accompanying technical\n\
             declaration) into evidence. Copies of the `.fab` bundle, the detached `.far` production\n\
             receipt, the discovery load files, and the standalone `fa-verify` verification procedure\n\
             are provided herewith for inspection and independent cryptographic verification.\n"
        );

        Self {
            matter_id,
            book_id_hex,
            branch_id_hex,
            through_seq,
            leaf_count,
            checkpoint_oid_hex,
            bundle_digest_hex,
            signer_key_id_hex,
            signer_public_key_hex,
            produced_at_seq,
            document_commitments,
            declaration_template_md,
            verification_procedure_md,
            adverse_party_notice_template_md,
        }
    }
}

/// Complete output of a matter-scoped litigation production over an authenticated
/// `.fab` bundle and signed receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatterProductionPackage {
    pub matter_id: String,
    pub bundle: Bundle,
    pub receipt: ProductionReceipt,
    pub bates_assignments: Vec<BatesAssignment>,
    pub privilege_log: PrivilegeLog,
    pub fre902: Fre902Package,
}

/// Assemble a [`MatterProductionPackage`] from an already-produced [`Bundle`],
/// its [`StoredCheckpoint`], its signed [`ProductionReceipt`], the capability-filtered
/// `reads` observed during bundle assembly, optional `page_counts` per document
/// (defaults to 1 page per 4 KiB chunk), `withheld_in_full` document OIDs, and
/// `privilege_metadata`.
///
/// The source documents in the book are never mutated; Bates ranges and exhibit
/// marks are tracked in `registry` per matter.
#[allow(clippy::too_many_arguments)]
pub fn assemble_matter_package(
    matter_id: &str,
    bundle: Bundle,
    checkpoint: &StoredCheckpoint,
    receipt: ProductionReceipt,
    signer_public_key: &[u8; 32],
    reads: &BTreeMap<Oid, DocumentRead>,
    page_counts: &BTreeMap<Oid, u64>,
    withheld_in_full: &[Oid],
    privilege_metadata: &BTreeMap<Oid, PrivilegeMetadata>,
    registry: &mut MatterProductionRegistry,
) -> Result<MatterProductionPackage, KernelError> {
    let mut bates_assignments = Vec::with_capacity(reads.len());
    for (oid, read) in reads {
        let (doc_commit, default_pages) = match read {
            DocumentRead::Full(doc) => {
                let chunks = (doc.bytes.len() as u64)
                    .div_ceil(fa_journal::evidence::CHUNK_BYTES as u64)
                    .max(1);
                (doc.doc_commit(), chunks)
            }
            DocumentRead::Redacted(view) => (view.doc_commit, (view.chunks.len() as u64).max(1)),
        };
        let pages = page_counts
            .get(oid)
            .copied()
            .unwrap_or(default_pages)
            .max(1);
        let assignment = registry
            .assign_bates(matter_id, *oid, doc_commit, pages)
            .map_err(|e| KernelError::Corrupt(e.to_string()))?;
        bates_assignments.push(assignment);
    }

    let privilege_log = PrivilegeLog::build(
        matter_id,
        reads,
        withheld_in_full,
        privilege_metadata,
        registry,
    )
    .map_err(|e| KernelError::Corrupt(e.to_string()))?;

    let fre902 = Fre902Package::generate(
        matter_id,
        &bundle,
        checkpoint,
        &receipt,
        signer_public_key,
        &bates_assignments,
    );

    Ok(MatterProductionPackage {
        matter_id: matter_id.to_string(),
        bundle,
        receipt,
        bates_assignments,
        privilege_log,
        fre902,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Statement;
    use crate::bundle::ReceiptBody;
    use crate::checkpoint::{CheckpointBody, TransparencyCheckpoint};
    use crate::sign::{CheckpointSigner, SigningKey};
    use fa_journal::{Document, ViewChunk};
    use fa_model::Id128;

    #[test]
    fn production_profile_and_exhibit_mark_round_trip() {
        let mut profile =
            ProductionProfile::new("SEC-2026-0042", "ACME-SEC", 1, LoadFileFormat::Both).unwrap();
        profile.protective_order_oid = Some(Oid([0x11; 32]));
        profile
            .designations
            .insert(Oid([0x22; 32]), ConfidentialityDesignation::Confidential);
        profile.designations.insert(
            Oid([0x33; 32]),
            ConfidentialityDesignation::AttorneysEyesOnly,
        );

        let bytes = profile.canonical_bytes().unwrap();
        let decoded = ProductionProfile::decode(&bytes).unwrap();
        assert_eq!(decoded, profile);
        assert_eq!(decoded.oid().unwrap(), profile.oid().unwrap());

        let mark = ExhibitMark::new(
            Oid([0x22; 32]),
            "PX-042",
            "SEC-2026-0042",
            VId(77),
            [0x99; 32],
        )
        .unwrap();
        let mark_bytes = mark.canonical_bytes().unwrap();
        let mark_decoded = ExhibitMark::decode(&mark_bytes).unwrap();
        assert_eq!(mark_decoded, mark);
        assert_eq!(mark_decoded.oid().unwrap(), mark.oid().unwrap());
    }

    #[test]
    fn multi_matter_bates_assignment_preserves_source_doc_commit_and_idempotency() {
        let doc = Document {
            book_id: Id128([1; 16]),
            kind: 1,
            mime: "application/pdf".to_string(),
            bytes: b"invoice #1042 original bytes".to_vec(),
            grade: 1,
            retrieved_by: VId(10),
        };
        let original_commit = doc.doc_commit();
        let doc_oid = doc.oid();

        let mut registry = MatterProductionRegistry::new();
        registry
            .register_profile(
                ProductionProfile::new(
                    "MATTER-SEC",
                    "ACME-SEC",
                    1,
                    LoadFileFormat::ConcordanceDatOpt,
                )
                .unwrap(),
            )
            .unwrap();
        registry
            .register_profile(
                ProductionProfile::new("MATTER-CIVIL", "ACME-CIV", 500, LoadFileFormat::EdrmXml)
                    .unwrap(),
            )
            .unwrap();

        let bates_sec_1 = registry
            .assign_bates("MATTER-SEC", doc_oid, original_commit, 3)
            .unwrap();
        assert_eq!(bates_sec_1.beg_bates(), "ACME-SEC-00000001");
        assert_eq!(bates_sec_1.end_bates(), "ACME-SEC-00000003");
        assert_eq!(bates_sec_1.doc_commit, original_commit);

        // Producing the same document again in MATTER-SEC returns the exact same Bates range.
        let bates_sec_2 = registry
            .assign_bates("MATTER-SEC", doc_oid, original_commit, 3)
            .unwrap();
        assert_eq!(bates_sec_2, bates_sec_1);
        assert_eq!(registry.profile("MATTER-SEC").unwrap().next_bates, 4);

        // Producing the same document in MATTER-CIVIL assigns MATTER-CIVIL's Bates range
        // while preserving MATTER-SEC's Bates range and leaving doc.doc_commit() unchanged.
        let bates_civ = registry
            .assign_bates("MATTER-CIVIL", doc_oid, original_commit, 3)
            .unwrap();
        assert_eq!(bates_civ.beg_bates(), "ACME-CIV-00000500");
        assert_eq!(bates_civ.end_bates(), "ACME-CIV-00000502");
        assert_eq!(doc.doc_commit(), original_commit);

        let all_for_doc = registry.bates_for_document(&doc_oid);
        assert_eq!(all_for_doc.len(), 2);
        assert_eq!(all_for_doc[0].matter_id, "MATTER-CIVIL");
        assert_eq!(all_for_doc[1].matter_id, "MATTER-SEC");
    }

    #[test]
    fn privilege_log_and_fre902_package_reflect_redactions_and_technical_predicates() {
        let doc_redacted_oid = Oid([0xAA; 32]);
        let doc_withheld_oid = Oid([0xBB; 32]);

        let view = RedactedView {
            original: doc_redacted_oid,
            doc_commit: [0x11; 32],
            kind: 1,
            size: 8192,
            contract: 1,
            chunks: vec![
                ViewChunk::Disclosed(vec![b'a'; 4096]),
                ViewChunk::Withheld([0x22; 32]),
            ],
        };
        let mut reads = BTreeMap::new();
        reads.insert(doc_redacted_oid, DocumentRead::Redacted(view));

        let mut metadata = BTreeMap::new();
        metadata.insert(
            doc_redacted_oid,
            PrivilegeMetadata {
                document_oid: doc_redacted_oid,
                doc_commit: [0x11; 32],
                date: DateDay::from_ymd(2026, 3, 15).unwrap(),
                author: "Controller <controller@acme.example>".into(),
                recipients: vec!["Outside Counsel <counsel@firm.example>".into()],
                description: "Board packet with legal advice section on chunk 1".into(),
                basis: "Attorney-Client Privilege (Contract 1)".into(),
            },
        );
        metadata.insert(
            doc_withheld_oid,
            PrivilegeMetadata {
                document_oid: doc_withheld_oid,
                doc_commit: [0x33; 32],
                date: DateDay::from_ymd(2026, 3, 20).unwrap(),
                author: "General Counsel <gc@acme.example>".into(),
                recipients: vec!["CFO <cfo@acme.example>".into()],
                description: "Litigation strategy memorandum".into(),
                basis: "Work-Product Doctrine".into(),
            },
        );

        let mut registry = MatterProductionRegistry::new();
        registry
            .register_profile(
                ProductionProfile::new("MATTER-SEC", "ACME-SEC", 10, LoadFileFormat::Both).unwrap(),
            )
            .unwrap();

        let key = SigningKey::from_seed(&[7; 32]);
        let statement = Statement {
            book_id: Id128([1; 16]),
            branch_id: Id128([2; 16]),
            through_seq: CommitSeq(50),
            leaf_count: 12,
            root: [3; 32],
        };
        let cp = TransparencyCheckpoint::sign(
            CheckpointBody {
                statement,
                state_oid: Oid([9; 32]),
                scope_index_root: [4; 32],
                substrate_chain_commitment: [5; 32],
                witness_policy_oid: None,
                time_evidence_oid: None,
            },
            &[&key as &dyn CheckpointSigner],
        )
        .unwrap();
        let cp_bytes = cp.canonical_bytes().unwrap();
        let stored_cp = StoredCheckpoint {
            vid: VId(900),
            oid: cp.oid().unwrap(),
            checkpoint: cp,
            bytes: cp_bytes,
        };
        let bundle = Bundle {
            bytes: b"synthetic-bundle-bytes".to_vec(),
            digest: [6; 32],
        };
        let receipt = ProductionReceipt::sign(
            ReceiptBody {
                bundle_digest: bundle.digest,
                producer_principal: VId(42),
                produced_at_seq: CommitSeq(55),
                capability_commitment: [8; 32],
                time_evidence_oid: None,
            },
            &key,
        )
        .unwrap();

        let pkg = assemble_matter_package(
            "MATTER-SEC",
            bundle,
            &stored_cp,
            receipt,
            &key.public_key(),
            &reads,
            &BTreeMap::new(),
            &[doc_withheld_oid],
            &metadata,
            &mut registry,
        )
        .unwrap();

        assert_eq!(pkg.privilege_log.rows.len(), 2);
        assert_eq!(
            pkg.privilege_log.rows[0].treatment,
            PrivilegeTreatment::RedactedInPart {
                contract_id: 1,
                withheld_chunks: 1,
                total_chunks: 2,
            }
        );
        assert_eq!(
            pkg.privilege_log.rows[0].bates_range.as_deref(),
            Some("ACME-SEC-00000010..=ACME-SEC-00000011")
        );
        assert_eq!(
            pkg.privilege_log.rows[1].treatment,
            PrivilegeTreatment::WithheldInFull
        );
        assert_eq!(pkg.privilege_log.rows[1].bates_range, None);

        let md = pkg.privilege_log.to_markdown();
        assert!(md.contains("REDACTED_IN_PART(contract=1, withheld_chunks=1/2)"));
        assert!(md.contains("WITHHELD_IN_FULL"));

        assert!(
            pkg.fre902
                .declaration_template_md
                .contains(&pkg.fre902.bundle_digest_hex)
        );
        assert!(
            pkg.fre902
                .verification_procedure_md
                .contains("fa-verify bundle")
        );
        assert!(
            pkg.fre902
                .adverse_party_notice_template_md
                .contains("MATTER-SEC")
        );
    }
}
