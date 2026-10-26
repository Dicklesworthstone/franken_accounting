//! Litigation production tooling: projections over journaled [`fa_journal::ProductionProfile`]
//! and [`fa_journal::BatesRange`] vertices, privilege logs, and FRE 902(13)/(14) technical
//! certification packages (plan §11.8, §13.2–§13.4, Appendix A; beads `fa-6l9`, `fa-9ccl`).
//!
//! All litigation production metadata lives in the journal (`fa_journal::production`
//! and `fa_journal::attestation`) outside the immutable `Document` payload so
//! `doc_commit` never changes when a document is Bates-stamped, designated under
//! a protective order, or marked as an exhibit in one or more matters.

use std::collections::BTreeMap;

use fa_journal::{DocumentRead, KernelError, Produced, ProductionView, RedactedView};
use fa_model::{DecodeError, EncodeError, Oid};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::CommitSeq;

use crate::bundle::{Bundle, ProductionReceipt};
use crate::state::StoredCheckpoint;

pub const PRIVILEGE_LOG_DOMAIN: &[u8] = b"fa:privilege-log:v1";
pub const MAX_BATES_PREFIX_BYTES: usize = fa_journal::production::MAX_BATES_PREFIX_BYTES;
pub const MAX_MATTER_ID_BYTES: usize = fa_journal::production::MAX_MATTER_BYTES;
pub const MAX_EXHIBIT_LABEL_BYTES: usize = fa_journal::attestation::MAX_EXHIBIT_LABEL_BYTES;

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

/// Load-file format selector on a [`fa_journal::ProductionProfile`] (Appendix A `load_file_format: u8`).
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

/// Errors returned when validating or projecting litigation production metadata.
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

/// Contiguous Bates number range assigned to a document in a specific matter (plan §13.2),
/// projected from a journaled [`fa_journal::BatesRange`] and [`fa_journal::ProductionProfile`].
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
    /// Project a journaled [`fa_journal::BatesRange`] under its [`fa_journal::ProductionProfile`].
    pub fn from_journaled(
        profile: &fa_journal::ProductionProfile,
        range: &fa_journal::BatesRange,
    ) -> Result<Self, ProductionError> {
        let designation = ConfidentialityDesignation::from_tag(range.designation)
            .ok_or(ProductionError::InvalidField("designation"))?;
        Ok(Self {
            document_oid: range.document,
            doc_commit: range.doc_commit,
            matter_id: profile.matter.clone(),
            bates_prefix: profile.bates_prefix.clone(),
            start_number: range.start,
            end_number: range.end,
            page_count: range.pages(),
            designation,
        })
    }

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

/// Project every [`BatesAssignment`] from a journaled [`Produced`] outcome.
pub fn bates_assignments_from_produced(
    produced: &Produced,
) -> Result<Vec<BatesAssignment>, ProductionError> {
    produced
        .ranges
        .iter()
        .map(|r| BatesAssignment::from_journaled(&produced.profile, &r.range))
        .collect()
}

/// Project every [`BatesAssignment`] from a journaled [`ProductionView`].
pub fn bates_assignments_from_view(
    view: &ProductionView,
) -> Result<Vec<BatesAssignment>, ProductionError> {
    view.ranges
        .iter()
        .map(|r| BatesAssignment::from_journaled(&view.profile, &r.range))
        .collect()
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
    /// the matter's journaled [`BatesAssignment`] projections.
    pub fn build(
        matter_id: impl Into<String>,
        reads: &BTreeMap<Oid, DocumentRead>,
        withheld_in_full: &[Oid],
        metadata: &BTreeMap<Oid, PrivilegeMetadata>,
        assignments: &[BatesAssignment],
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
                    let bates_range = assignments
                        .iter()
                        .find(|a| a.matter_id == matter_id && &a.document_oid == oid)
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
/// `reads` observed during bundle assembly, the journaled [`BatesAssignment`]
/// projections, `withheld_in_full` document OIDs, and `privilege_metadata`.
#[allow(clippy::too_many_arguments)]
pub fn assemble_matter_package(
    matter_id: &str,
    bundle: Bundle,
    checkpoint: &StoredCheckpoint,
    receipt: ProductionReceipt,
    signer_public_key: &[u8; 32],
    reads: &BTreeMap<Oid, DocumentRead>,
    bates_assignments: Vec<BatesAssignment>,
    withheld_in_full: &[Oid],
    privilege_metadata: &BTreeMap<Oid, PrivilegeMetadata>,
) -> Result<MatterProductionPackage, KernelError> {
    let privilege_log = PrivilegeLog::build(
        matter_id,
        reads,
        withheld_in_full,
        privilege_metadata,
        &bates_assignments,
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
    use fa_journal::{BatesRange, ProductionProfile as JournalProfile, ViewChunk};
    use fa_model::Id128;
    use fgdb_types::VId;

    #[test]
    fn bates_assignment_projects_journaled_profile_and_range() {
        let profile = JournalProfile {
            book_id: Id128([1; 16]),
            matter: "SEC-2026-0042".into(),
            bates_prefix: "ACME-SEC".into(),
            first_bates: 1,
            load_file_format: LoadFileFormat::Both.tag(),
            protective_order: Some(Oid([0x11; 32])),
        };
        let range = BatesRange {
            document: Oid([0x22; 32]),
            doc_commit: [0x99; 32],
            start: 1,
            end: 3,
            designation: ConfidentialityDesignation::Confidential.tag(),
        };
        let assignment = BatesAssignment::from_journaled(&profile, &range).unwrap();
        assert_eq!(assignment.beg_bates(), "ACME-SEC-00000001");
        assert_eq!(assignment.end_bates(), "ACME-SEC-00000003");
        assert_eq!(
            assignment.range_label(),
            "ACME-SEC-00000001..=ACME-SEC-00000003"
        );
        assert_eq!(
            assignment.designation,
            ConfidentialityDesignation::Confidential
        );
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

        let assignments = vec![BatesAssignment {
            document_oid: doc_redacted_oid,
            doc_commit: [0x11; 32],
            matter_id: "MATTER-SEC".into(),
            bates_prefix: "ACME-SEC".into(),
            start_number: 10,
            end_number: 11,
            page_count: 2,
            designation: ConfidentialityDesignation::Confidential,
        }];

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
            assignments,
            &[doc_withheld_oid],
            &metadata,
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
