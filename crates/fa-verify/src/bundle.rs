//! Evidence bundles (`.fab`; plan §13.2, Appendix A `Bundle` and
//! `ProductionReceipt`), on the verifier's side.
//!
//! ```text
//! bundle   = bytes("fa:bundle:v1") ‖ format_major u16 ‖ format_minor u16
//!          ‖ manifest ‖ bytes(TransparencyCheckpoint) ‖ completeness proof
//!          ‖ list(entry) ‖ list(balance) ‖ bytes(manifest_md)
//! manifest = book_id [16] ‖ branch_id [16] ‖ through_seq u64 ‖ leaf_count u64
//!          ‖ checkpoint_oid [32]
//!          ‖ scope:        1 Prefix
//!                        | 2 Account  account u128 ‖ from i32 ‖ to i32
//!                        | 3 Entries  list(leaf_index u64), strictly ascending
//!          ‖ completeness: 1 SeqRangeComplete  from u64 ‖ to u64
//!                        | 2 ScopeIndexComplete
//!                        | 3 FilterAttested
//! completeness proof = scope 1: bytes(PrefixProof)
//!                    | scope 2: bytes(ScopeProof)
//!                    | scope 3: list(bytes(LeafEnvelope) ‖ list([32] accumulator path)),
//!                               one per listed leaf, in the manifest's order
//! entry    = leaf_index u64 ‖ proposal_len u32 ‖ bytes(record) ‖ list(stub),
//!            strictly ascending by leaf_index
//! stub     = doc_commit [32] ‖ kind u8 ‖ length u64 ‖ chunk_root [32]
//!            ‖ opt(bytes(document)), strictly ascending by doc_commit
//! balance  = bytes(fold_domain) ‖ fold_version u16 ‖ bytes(BalanceProof)
//!
//! bundle_digest  = BLAKE3("fa:bundle:v1" ‖ bundle)     computed, never read from the file
//!
//! receipt  = body ‖ signer_key_id [32] ‖ scheme u16 ‖ bytes(signature)
//! body     = bytes("fa:production-receipt:v1") ‖ bundle_digest [32]
//!          ‖ producer_principal u128 ‖ produced_at_seq u64
//!          ‖ capability_commitment [32] ‖ opt([32] time_evidence_oid)
//! receipt_digest = BLAKE3("fa:production-receipt:v1" ‖ body)
//! signed message = "fa:production-receipt-signature:v1" ‖ receipt_digest
//! ```
//!
//! The body is deterministic: the same scope against the same checkpoint
//! is the same bytes, so two productions of the same material compare
//! equal. Who produced it, when, and under which capability live in the
//! detached receipt, which signs the body's digest.
//!
//! `format_major.format_minor` is the fa-verify format the bundle targets;
//! this verifier implements 1.0 and refuses any other version before it
//! reads further ([`BundleError::Version`]). Each balance names the
//! register fold law its claim is defined under, and a law this verifier
//! does not implement is a typed failure of that balance
//! ([`VerifyError::FoldLaw`]), never a recomputation under another law.
//!
//! A scope admits exactly one completeness claim: `Prefix` is
//! `SeqRangeComplete(0, leaf_count)`, `Account` is `ScopeIndexComplete`,
//! and `Entries` is `FilterAttested`, reported as `membership_only` and
//! never as complete. An `Account` bundle's completeness rests on the
//! scope index root its checkpoint signs; the report names that premise
//! and the keys it rests on, since the bundle carries no complete prefix
//! to recompute the index from.
//!
//! A stub's `kind`, `length` and `chunk_root` are exactly what `doc_commit`
//! commits (`BLAKE3("fa:doc:v1" ‖ kind ‖ length ‖ chunk_root)`), so every
//! stub is checked against its commitment whether or not the document's
//! bytes are included; included bytes must also produce that chunk root
//! and length.
//!
//! [`verify_bundle`] grades every predicate on its own — the checkpoint's
//! signature, the manifest, the completeness of the in-scope set, the
//! entry set, each record, each entry's document closure, each document
//! stub's public commitment, each balance, and the receipt — as pass,
//! fail, or unrun when a predicate it rests on failed. There is no
//! bundle-wide success bit.
//!
//! Version 1.0 carries a subset of Appendix A's bundle, by name: closures
//! hold the documents an entry's own evidence list cites (no events,
//! rules, approvals, supplemental evidence or attestations); there are no
//! redaction contracts, register cells, statements, certificates or
//! findings; the receipt's `time_evidence_oid` is absent until TimeEvidence
//! is bound (a registered interim). `scope_label` and `bundle_digest` are
//! derived, not stored, so neither can disagree with what it labels.

use std::collections::BTreeMap;
use std::fmt;

use crate::blake3::{hash_parts, hex};
use crate::checkpoint::{SCHEME_ED25519, SignedCheckpoint, signer_key_id, verify_checkpoint};
use crate::codec::{DecodeError, Reader, Reason};
use crate::document::{chunk_root, commit_of};
use crate::ed25519::{self, SignatureError};
use crate::envelope::{LeafEnvelope, check_record, cited_documents};
use crate::proof::{
    MAX_ENVELOPE_BYTES, SCOPE_SEQ_RANGE_COMPLETE, VerifyError, read_path, verify_prefix, within,
};
use crate::scope::{SCOPE_INDEX_COMPLETE, ScopeClaim, verify_scope};
use crate::tree::{Digest, leaf_hash, root_from_inclusion};
use crate::verify_balance;

pub const BUNDLE_FORMAT: &[u8] = b"fa:bundle:v1";
pub const BUNDLE_DIGEST_DOMAIN: &[u8] = b"fa:bundle:v1";
/// The fa-verify format this verifier implements.
pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 0;
pub const RECEIPT_FORMAT: &[u8] = b"fa:production-receipt:v1";
pub const RECEIPT_DIGEST_DOMAIN: &[u8] = b"fa:production-receipt:v1";
pub const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"fa:production-receipt-signature:v1";
/// The register fold law the balance recomputation implements: posted
/// debits and credits of (account, unit), holds excluded, through an
/// inclusive effective-day cutoff — the stock value the book's registers
/// fold under `fa:register-fold:v2`.
pub const FOLD_DOMAIN: &[u8] = b"fa:register-fold:v2";
pub const FOLD_VERSION: u16 = 2;

pub const SCOPE_MEMBERSHIP_ONLY: &str = "membership_only";

pub const SCOPE_PREFIX: u8 = 1;
pub const SCOPE_ACCOUNT: u8 = 2;
pub const SCOPE_ENTRIES: u8 = 3;
pub const COMPLETENESS_SEQ_RANGE: u8 = 1;
pub const COMPLETENESS_SCOPE_INDEX: u8 = 2;
pub const COMPLETENESS_FILTER_ATTESTED: u8 = 3;

/// `max_document_bytes` (`registries/evidence_policy.toml`).
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 1 << 24;
const MAX_STUBS: usize = 4096;
const MAX_BALANCES: usize = 4096;
const MAX_CHECKPOINT_BYTES: usize = 1 << 20;
const MAX_DOMAIN_BYTES: usize = 64;
const MAX_MANIFEST_MD_BYTES: usize = 1 << 20;
const MAX_SIGNATURE_BYTES: usize = 1024;
/// A proof section is bounded by the input that holds it.
const UNBOUNDED: usize = usize::MAX;

/// What the bundle covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleScope {
    /// Every leaf of the checkpoint's prefix.
    Prefix,
    /// One account's entries with an effective day in an interval.
    Account(ScopeClaim),
    /// Named leaves, ascending.
    Entries(Vec<u64>),
}

/// The completeness the manifest claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completeness {
    SeqRangeComplete { from: u64, to: u64 },
    ScopeIndexComplete,
    FilterAttested,
}

impl Completeness {
    /// The scope label the claim is reported under.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::SeqRangeComplete { .. } => SCOPE_SEQ_RANGE_COMPLETE,
            Self::ScopeIndexComplete => SCOPE_INDEX_COMPLETE,
            Self::FilterAttested => SCOPE_MEMBERSHIP_ONLY,
        }
    }
}

impl BundleScope {
    /// The one completeness claim this scope admits.
    #[must_use]
    pub fn admissible(&self, leaf_count: u64) -> Completeness {
        match self {
            Self::Prefix => Completeness::SeqRangeComplete {
                from: 0,
                to: leaf_count,
            },
            Self::Account(_) => Completeness::ScopeIndexComplete,
            Self::Entries(_) => Completeness::FilterAttested,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub book_id: [u8; 16],
    pub branch_id: [u8; 16],
    pub through_seq: u64,
    pub leaf_count: u64,
    pub checkpoint_oid: Digest,
    pub scope: BundleScope,
    pub completeness: Completeness,
}

/// What `manifest_md` summarizes beside the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub format: (u16, u16),
    pub entries: u64,
    /// Document stubs over every entry (a document cited by two entries
    /// counts twice).
    pub documents: u64,
    pub inline: u64,
    /// The fold law of each balance, in body order.
    pub balances: Vec<(Vec<u8>, u16)>,
}

/// The civil date of a day count since 1970-01-01 (proleptic Gregorian).
#[must_use]
pub fn civil(day: i32) -> String {
    let z = i64::from(day) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The human-readable text a bundle's manifest generates. The verifier
/// regenerates it and compares bytes, so the text cannot say something
/// the manifest does not.
#[must_use]
pub fn manifest_md(m: &Manifest, summary: &Summary) -> String {
    let scope = match &m.scope {
        BundleScope::Prefix => "every leaf of the journal prefix".to_string(),
        BundleScope::Account(c) => format!(
            "account {:032x}, entries effective {} through {}",
            c.account,
            civil(c.from),
            civil(c.to)
        ),
        BundleScope::Entries(leaves) => format!("{} named journal leaves", leaves.len()),
    };
    let meaning = match m.completeness {
        Completeness::SeqRangeComplete { from, to } => format!(
            "leaves {from} to {to}: every leaf is listed and recomputes the checkpoint's root"
        ),
        Completeness::ScopeIndexComplete => "the account's entries in the interval are one gap-free run of the checkpoint's signed scope index".to_string(),
        Completeness::FilterAttested => "each listed entry is in the journal; nothing is said about entries not listed".to_string(),
    };
    let mut laws: Vec<(Vec<u8>, u16)> = summary.balances.clone();
    laws.sort();
    laws.dedup();
    let laws = if laws.is_empty() {
        String::new()
    } else {
        let named: Vec<String> = laws
            .iter()
            .map(|(d, v)| format!("{} version {v}", String::from_utf8_lossy(d)))
            .collect();
        format!(", under register fold {}", named.join("; "))
    };
    format!(
        "# FrankenAccounting evidence bundle\n\
         \n\
         - Format: fa:bundle:v1, for fa-verify format {}.{}\n\
         - Book: {}\n\
         - Branch: {}\n\
         - Known at: commit sequence {} ({} journal leaves)\n\
         - Checkpoint: {}\n\
         - Scope: {scope}\n\
         - Completeness: {} ({meaning})\n\
         - Entries: {}, with their payloads\n\
         - Documents: {} cited, {} included\n\
         - Balances: {}{laws}\n\
         \n\
         Verify: fa-verify bundle <this file> --key <the book's checkpoint public key> [--receipt <its production receipt>]\n\
         \n\
         This text restates the manifest. It verifies nothing: fa-verify's report is the verification.\n",
        summary.format.0,
        summary.format.1,
        hex(&m.book_id),
        hex(&m.branch_id),
        m.through_seq,
        m.leaf_count,
        hex(&m.checkpoint_oid),
        m.completeness.label(),
        summary.entries,
        summary.documents,
        summary.inline,
        summary.balances.len(),
    )
}

/// `BLAKE3("fa:bundle:v1" ‖ bundle)`.
#[must_use]
pub fn bundle_digest(bundle: &[u8]) -> Digest {
    hash_parts(BUNDLE_DIGEST_DOMAIN, &[bundle])
}

/// Why a bundle could not be read at all. Everything past reading is a
/// graded check, never one of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// The bytes are not an `fa:bundle:v1` bundle.
    Format,
    /// The bundle targets an fa-verify format this verifier does not
    /// implement.
    Version {
        major: u16,
        minor: u16,
    },
    Decode(DecodeError),
    /// A key the caller named as trusted cannot be a validly generated
    /// Ed25519 key.
    TrustedKey {
        signer_key_id: Digest,
        reason: SignatureError,
    },
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format => write!(f, "not an `fa:bundle:v1` evidence bundle"),
            Self::Version { major, minor } => write!(
                f,
                "the bundle targets fa-verify format {major}.{minor}; this verifier implements {FORMAT_MAJOR}.{FORMAT_MINOR} only — use a verifier that implements {major}.{minor}"
            ),
            Self::Decode(e) => write!(f, "{e}"),
            Self::TrustedKey {
                signer_key_id,
                reason,
            } => write!(
                f,
                "trusted key {} cannot be trusted: {reason}",
                hex(signer_key_id)
            ),
        }
    }
}

impl core::error::Error for BundleError {}

impl From<DecodeError> for BundleError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// A predicate's grade: three states, and only `Pass` is green.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grade {
    Pass,
    Fail(String),
    /// Not evaluated: a predicate it rests on did not pass.
    Unrun(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleCheck {
    pub check: &'static str,
    pub scope: &'static str,
    pub subject: String,
    pub grade: Grade,
}

/// The facts a verified receipt states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptFacts {
    pub producer_principal: u128,
    pub produced_at_seq: u64,
    pub capability_commitment: Digest,
    pub time_evidence_oid: Option<Digest>,
    pub signed_by: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleReport {
    pub digest: Digest,
    pub manifest: Manifest,
    pub summary: Summary,
    pub checks: Vec<BundleCheck>,
    /// Present when a receipt was supplied and verified.
    pub receipt: Option<ReceiptFacts>,
}

impl BundleReport {
    /// Every predicate passed.
    #[must_use]
    pub fn verified(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| matches!(c.grade, Grade::Pass))
    }
}

// ---- decoding ------------------------------------------------------------------

struct Stub<'a> {
    doc_commit: Digest,
    kind: u8,
    length: u64,
    chunk_root: Digest,
    inline: Option<&'a [u8]>,
}

struct Item<'a> {
    leaf_index: u64,
    proposal_len: usize,
    record: &'a [u8],
    stubs: Vec<Stub<'a>>,
}

struct BalanceItem<'a> {
    domain: &'a [u8],
    version: u16,
    proof: &'a [u8],
}

enum ProofSection<'a> {
    Prefix(&'a [u8]),
    Scope(&'a [u8]),
    Members(Vec<(&'a [u8], Vec<Digest>)>),
}

struct Parsed<'a> {
    format: (u16, u16),
    manifest: Manifest,
    checkpoint: &'a [u8],
    proof: ProofSection<'a>,
    entries: Vec<Item<'a>>,
    balances: Vec<BalanceItem<'a>>,
    manifest_md: &'a [u8],
}

fn read_manifest(r: &mut Reader<'_>) -> Result<Manifest, DecodeError> {
    let book_id = r.fixed("manifest.book_id")?;
    let branch_id = r.fixed("manifest.branch_id")?;
    let through_seq = r.u64("manifest.through_seq")?;
    let leaf_count = r.u64("manifest.leaf_count")?;
    let checkpoint_oid = r.fixed("manifest.checkpoint_oid")?;
    let scope = match r.u8("manifest.scope")? {
        SCOPE_PREFIX => BundleScope::Prefix,
        SCOPE_ACCOUNT => BundleScope::Account(ScopeClaim {
            account: r.u128("manifest.scope.account")?,
            from: r.i32("manifest.scope.from")?,
            to: r.i32("manifest.scope.to")?,
        }),
        SCOPE_ENTRIES => {
            let n = r.count(MAX_ENTRIES, 8, "manifest.scope.leaves")?;
            let mut leaves = Vec::with_capacity(n);
            for _ in 0..n {
                leaves.push(r.u64("manifest.scope.leaf")?);
            }
            if !leaves.windows(2).all(|w| w[0] < w[1]) {
                return Err(r.error("manifest.scope.leaves", Reason::Unsorted));
            }
            BundleScope::Entries(leaves)
        }
        t => return Err(r.error("manifest.scope", Reason::BadTag(t))),
    };
    let completeness = match r.u8("manifest.completeness")? {
        COMPLETENESS_SEQ_RANGE => Completeness::SeqRangeComplete {
            from: r.u64("manifest.completeness.from")?,
            to: r.u64("manifest.completeness.to")?,
        },
        COMPLETENESS_SCOPE_INDEX => Completeness::ScopeIndexComplete,
        COMPLETENESS_FILTER_ATTESTED => Completeness::FilterAttested,
        t => return Err(r.error("manifest.completeness", Reason::BadTag(t))),
    };
    Ok(Manifest {
        book_id,
        branch_id,
        through_seq,
        leaf_count,
        checkpoint_oid,
        scope,
        completeness,
    })
}

fn read_stubs<'a>(r: &mut Reader<'a>) -> Result<Vec<Stub<'a>>, DecodeError> {
    let n = r.count(MAX_STUBS, 32 + 1 + 8 + 32 + 1, "entry.stubs")?;
    let mut stubs: Vec<Stub<'a>> = Vec::with_capacity(n);
    for _ in 0..n {
        let doc_commit = r.fixed("stub.doc_commit")?;
        let kind = r.u8("stub.kind")?;
        let length = r.u64("stub.length")?;
        let chunk_root = r.fixed("stub.chunk_root")?;
        let inline = if r.present("stub.document")? {
            Some(r.bytes(MAX_DOCUMENT_BYTES, "stub.document")?)
        } else {
            None
        };
        if stubs.last().is_some_and(|s| s.doc_commit >= doc_commit) {
            return Err(r.error("entry.stubs", Reason::Unsorted));
        }
        stubs.push(Stub {
            doc_commit,
            kind,
            length,
            chunk_root,
            inline,
        });
    }
    Ok(stubs)
}

fn parse(bundle: &[u8]) -> Result<Parsed<'_>, BundleError> {
    let mut r = Reader::new(bundle);
    if r.bytes(64, "bundle.format").ok() != Some(BUNDLE_FORMAT) {
        return Err(BundleError::Format);
    }
    let major = r.u16("bundle.format_major")?;
    let minor = r.u16("bundle.format_minor")?;
    if (major, minor) != (FORMAT_MAJOR, FORMAT_MINOR) {
        return Err(BundleError::Version { major, minor });
    }
    let manifest = read_manifest(&mut r)?;
    let checkpoint = r.bytes(MAX_CHECKPOINT_BYTES, "bundle.checkpoint")?;
    let proof = match &manifest.scope {
        BundleScope::Prefix => ProofSection::Prefix(r.bytes(UNBOUNDED, "bundle.prefix_proof")?),
        BundleScope::Account(_) => ProofSection::Scope(r.bytes(UNBOUNDED, "bundle.scope_proof")?),
        BundleScope::Entries(_) => {
            let n = r.count(MAX_ENTRIES, 4 + 4, "bundle.members")?;
            let mut members = Vec::with_capacity(n);
            for _ in 0..n {
                let envelope = r.bytes(MAX_ENVELOPE_BYTES, "member.envelope")?;
                members.push((envelope, read_path(&mut r)?));
            }
            ProofSection::Members(members)
        }
    };
    let n = r.count(MAX_ENTRIES, 8 + 4 + 4 + 4, "bundle.entries")?;
    let mut entries: Vec<Item<'_>> = Vec::with_capacity(n);
    for _ in 0..n {
        let leaf_index = r.u64("entry.leaf_index")?;
        let proposal_len = usize::try_from(r.u32("entry.proposal_len")?).unwrap_or(usize::MAX);
        let record = r.bytes(crate::envelope::MAX_RECORD_BYTES, "entry.record")?;
        let stubs = read_stubs(&mut r)?;
        if entries.last().is_some_and(|e| e.leaf_index >= leaf_index) {
            return Err(r.error("bundle.entries", Reason::Unsorted).into());
        }
        entries.push(Item {
            leaf_index,
            proposal_len,
            record,
            stubs,
        });
    }
    let n = r.count(MAX_BALANCES, 4 + 2 + 4, "bundle.balances")?;
    let mut balances = Vec::with_capacity(n);
    for _ in 0..n {
        balances.push(BalanceItem {
            domain: r.bytes(MAX_DOMAIN_BYTES, "balance.fold_domain")?,
            version: r.u16("balance.fold_version")?,
            proof: r.bytes(UNBOUNDED, "balance.proof")?,
        });
    }
    let manifest_md = r.bytes(MAX_MANIFEST_MD_BYTES, "bundle.manifest_md")?;
    r.finish("bundle")?;
    Ok(Parsed {
        format: (major, minor),
        manifest,
        checkpoint,
        proof,
        entries,
        balances,
        manifest_md,
    })
}

// ---- grading ---------------------------------------------------------------------

fn check(check: &'static str, scope: &'static str, subject: String, grade: Grade) -> BundleCheck {
    BundleCheck {
        check,
        scope,
        subject,
        grade,
    }
}

fn graded<T, E: fmt::Display>(result: &Result<T, E>) -> Grade {
    match result {
        Ok(_) => Grade::Pass,
        Err(e) => Grade::Fail(e.to_string()),
    }
}

const CHECKPOINT_UNRUN: &str = "the checkpoint's signature did not verify";
const SCOPE_UNRUN: &str = "the in-scope envelopes are not authenticated";

fn manifest_grade(p: &Parsed<'_>, signed: &SignedCheckpoint, summary: &Summary) -> Grade {
    let m = &p.manifest;
    let cp = &signed.checkpoint;
    if (m.book_id, m.branch_id, m.through_seq, m.leaf_count)
        != (cp.book_id, cp.branch_id, cp.through_seq, cp.leaf_count)
    {
        return Grade::Fail(format!(
            "the manifest's coordinate (book {}, branch {}, through seq {}, {} leaves) is not the checkpoint's: {cp}",
            hex(&m.book_id),
            hex(&m.branch_id),
            m.through_seq,
            m.leaf_count
        ));
    }
    if m.checkpoint_oid != signed.oid {
        return Grade::Fail(format!(
            "the manifest names checkpoint {}; the bundle carries {}",
            hex(&m.checkpoint_oid),
            hex(&signed.oid)
        ));
    }
    let admissible = m.scope.admissible(m.leaf_count);
    if m.completeness != admissible {
        return Grade::Fail(format!(
            "the manifest claims {} for this scope; the only admissible claim is {}",
            m.completeness.label(),
            admissible.label()
        ));
    }
    if p.manifest_md != manifest_md(m, summary).as_bytes() {
        return Grade::Fail("manifest_md is not the text the manifest generates".to_string());
    }
    Grade::Pass
}

/// The in-scope leaves and their authenticated envelopes.
fn in_scope(
    p: &Parsed<'_>,
    signed: &SignedCheckpoint,
) -> Result<BTreeMap<u64, LeafEnvelope>, VerifyError> {
    let cp = &signed.checkpoint;
    match (&p.proof, &p.manifest.scope) {
        (ProofSection::Prefix(proof), BundleScope::Prefix) => Ok(verify_prefix(proof, cp)?
            .envelopes
            .into_iter()
            .zip(0u64..)
            .map(|(e, i)| (i, e))
            .collect()),
        (ProofSection::Scope(proof), BundleScope::Account(claim)) => {
            Ok(verify_scope(proof, signed, claim, None)?
                .leaves
                .into_iter()
                .collect())
        }
        (ProofSection::Members(members), BundleScope::Entries(leaves)) => {
            if members.len() != leaves.len() {
                return Err(VerifyError::LeafCount {
                    listed: u64::try_from(members.len()).unwrap_or(u64::MAX),
                    expected: u64::try_from(leaves.len()).unwrap_or(u64::MAX),
                });
            }
            let mut out = BTreeMap::new();
            for (index, (bytes, path)) in leaves.iter().zip(members) {
                let envelope = LeafEnvelope::decode(bytes)?;
                within(&envelope, cp)?;
                if root_from_inclusion(*index, cp.leaf_count, &leaf_hash(bytes), path)
                    != Some(cp.root)
                {
                    return Err(VerifyError::Inclusion);
                }
                out.insert(*index, envelope);
            }
            Ok(out)
        }
        // The section is read by the scope's tag, so the two always agree.
        _ => Err(VerifyError::ScopeClaim),
    }
}

/// The entries are exactly the in-scope leaves: name the first that is
/// missing or should not be there.
fn entry_set_grade(entries: &[Item<'_>], scope: &BTreeMap<u64, LeafEnvelope>) -> Grade {
    let listed: Vec<u64> = entries.iter().map(|e| e.leaf_index).collect();
    let wanted: Vec<u64> = scope.keys().copied().collect();
    let first_missing = wanted.iter().find(|i| listed.binary_search(i).is_err());
    let first_extra = listed.iter().find(|i| wanted.binary_search(i).is_err());
    match (first_missing, first_extra) {
        (None, None) => Grade::Pass,
        (Some(m), Some(x)) if x < m => Grade::Fail(format!(
            "leaf {x} has an entry but is not in scope (a padded entry)"
        )),
        (Some(m), _) => Grade::Fail(format!("in-scope leaf {m} has no entry (an omitted entry)")),
        (None, Some(x)) => Grade::Fail(format!(
            "leaf {x} has an entry but is not in scope (a padded entry)"
        )),
    }
}

/// Every `doc_commit` the entry's evidence cites has exactly one stub.
fn closure_grade(item: &Item<'_>) -> Grade {
    let Some(proposal) = item.record.get(..item.proposal_len) else {
        return Grade::Fail("the proposal length exceeds the record".to_string());
    };
    let cited = match cited_documents(proposal) {
        Ok(c) => c,
        Err(e) => return Grade::Fail(format!("the evidence list: {e}")),
    };
    let stubs: Vec<Digest> = item.stubs.iter().map(|s| s.doc_commit).collect();
    if let Some(missing) = cited.iter().find(|c| stubs.binary_search(c).is_err()) {
        return Grade::Fail(format!(
            "the entry cites document {} and the bundle has no stub for it",
            hex(missing)
        ));
    }
    if let Some(extra) = stubs.iter().find(|s| cited.binary_search(s).is_err()) {
        return Grade::Fail(format!(
            "the stub for document {} is not cited by the entry",
            hex(extra)
        ));
    }
    Grade::Pass
}

/// The stub's kind, length and chunk root are what its `doc_commit`
/// commits; included bytes are that document.
fn public_commitment_grade(stub: &Stub<'_>) -> Grade {
    let recomputed = commit_of(stub.kind, stub.length, &stub.chunk_root);
    if recomputed != stub.doc_commit {
        return Grade::Fail(format!(
            "kind {}, length {} and chunk root {} commit to {}, not {}",
            stub.kind,
            stub.length,
            hex(&stub.chunk_root),
            hex(&recomputed),
            hex(&stub.doc_commit)
        ));
    }
    let Some(bytes) = stub.inline else {
        return Grade::Pass;
    };
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if length != stub.length {
        return Grade::Fail(format!(
            "the included bytes are {length} long; the stub commits {}",
            stub.length
        ));
    }
    if chunk_root(bytes) != stub.chunk_root {
        return Grade::Fail(
            "the included bytes are not the committed document (their chunk root differs)"
                .to_string(),
        );
    }
    Grade::Pass
}

/// Why a receipt does not verify.
fn receipt_grade(
    receipt: &[u8],
    digest: &Digest,
    trusted_keys: &[[u8; 32]],
) -> Result<ReceiptFacts, String> {
    let mut r = Reader::new(receipt);
    if r.bytes(64, "receipt.format").ok() != Some(RECEIPT_FORMAT) {
        return Err("not an `fa:production-receipt:v1` receipt".to_string());
    }
    let read = |r: &mut Reader<'_>| -> Result<_, DecodeError> {
        let bundle_digest: Digest = r.fixed("receipt.bundle_digest")?;
        let producer_principal = r.u128("receipt.producer_principal")?;
        let produced_at_seq = r.u64("receipt.produced_at_seq")?;
        let capability_commitment: Digest = r.fixed("receipt.capability_commitment")?;
        let time_evidence_oid: Option<Digest> = if r.present("receipt.time_evidence_oid")? {
            Some(r.fixed("receipt.time_evidence_oid")?)
        } else {
            None
        };
        Ok((
            bundle_digest,
            producer_principal,
            produced_at_seq,
            capability_commitment,
            time_evidence_oid,
        ))
    };
    let (
        bundle_digest,
        producer_principal,
        produced_at_seq,
        capability_commitment,
        time_evidence_oid,
    ) = read(&mut r).map_err(|e| e.to_string())?;
    let body_len = receipt.len() - r.remaining();
    let key_id: Digest = r
        .fixed("receipt.signer_key_id")
        .map_err(|e| e.to_string())?;
    let scheme = r.u16("receipt.scheme").map_err(|e| e.to_string())?;
    let signature = r
        .bytes(MAX_SIGNATURE_BYTES, "receipt.signature")
        .map_err(|e| e.to_string())?;
    r.finish("receipt").map_err(|e| e.to_string())?;

    let Some(key) = trusted_keys.iter().find(|k| signer_key_id(k) == key_id) else {
        return Err(format!(
            "the receipt is signed by key {}, which you did not name as trusted",
            hex(&key_id)
        ));
    };
    if scheme != SCHEME_ED25519 {
        return Err(format!(
            "the receipt's signature scheme {scheme} is not Ed25519 (1)"
        ));
    }
    let signature: [u8; 64] = signature.try_into().map_err(|_| {
        format!(
            "the receipt's signature is {} bytes, not 64",
            signature.len()
        )
    })?;
    let mut message = RECEIPT_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&hash_parts(RECEIPT_DIGEST_DOMAIN, &[&receipt[..body_len]]));
    ed25519::verify(key, &message, &signature)
        .map_err(|e| format!("the receipt's signature does not verify: {e}"))?;
    if bundle_digest != *digest {
        return Err(format!(
            "the receipt is for bundle {}, not this one ({})",
            hex(&bundle_digest),
            hex(digest)
        ));
    }
    Ok(ReceiptFacts {
        producer_principal,
        produced_at_seq,
        capability_commitment,
        time_evidence_oid,
        signed_by: key_id,
    })
}

/// Verify an evidence bundle against the keys the caller trusts and, when
/// given, its production receipt. Every trusted key is admitted first (a
/// key that is not a curve point or is a small-order point is refused);
/// a bundle that cannot be read, or that targets another fa-verify format,
/// is refused whole. Everything else is graded predicate by predicate.
pub fn verify_bundle(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    receipt: Option<&[u8]>,
) -> Result<BundleReport, BundleError> {
    for key in trusted_keys {
        ed25519::check_public_key(key).map_err(|reason| BundleError::TrustedKey {
            signer_key_id: signer_key_id(key),
            reason,
        })?;
    }
    let p = parse(bundle)?;
    let digest = bundle_digest(bundle);
    let summary = Summary {
        format: p.format,
        entries: u64::try_from(p.entries.len()).unwrap_or(u64::MAX),
        documents: p
            .entries
            .iter()
            .map(|e| u64::try_from(e.stubs.len()).unwrap_or(u64::MAX))
            .sum(),
        inline: p
            .entries
            .iter()
            .flat_map(|e| &e.stubs)
            .filter(|s| s.inline.is_some())
            .count() as u64,
        balances: p
            .balances
            .iter()
            .map(|b| (b.domain.to_vec(), b.version))
            .collect(),
    };
    let mut checks = Vec::new();

    let signed = verify_checkpoint(p.checkpoint, trusted_keys);
    checks.push(check(
        "checkpoint",
        "signature",
        "the bundle's checkpoint".to_string(),
        graded(&signed),
    ));
    let signed = signed.ok();
    let scope_label = p.manifest.scope.admissible(p.manifest.leaf_count).label();

    checks.push(check(
        "manifest",
        "manifest",
        "the manifest and manifest_md".to_string(),
        signed.as_ref().map_or_else(
            || Grade::Unrun(CHECKPOINT_UNRUN.to_string()),
            |s| manifest_grade(&p, s, &summary),
        ),
    ));

    let scoped = signed.as_ref().map(|s| in_scope(&p, s));
    // The scope index root is signed, not recomputed here: an
    // `Account` bundle names that weaker premise (plan §13.2).
    let subject = match (&p.manifest.scope, &signed) {
        (BundleScope::Account(_), Some(s)) => format!(
            "the in-scope leaves; premise: the scope index as signed by {}, not recomputed from the journal",
            s.signed_by
                .iter()
                .map(|k| hex(k))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => "the in-scope leaves".to_string(),
    };
    checks.push(check(
        "completeness",
        scope_label,
        subject,
        match &scoped {
            None => Grade::Unrun(CHECKPOINT_UNRUN.to_string()),
            Some(r) => graded(r),
        },
    ));
    let scoped = scoped.and_then(Result::ok);

    checks.push(check(
        "entries",
        scope_label,
        "the entries are exactly the in-scope leaves".to_string(),
        scoped.as_ref().map_or_else(
            || Grade::Unrun(SCOPE_UNRUN.to_string()),
            |s| entry_set_grade(&p.entries, s),
        ),
    ));

    for item in &p.entries {
        let subject = format!("leaf {}", item.leaf_index);
        let record = match &scoped {
            None => Grade::Unrun(SCOPE_UNRUN.to_string()),
            Some(s) => match s.get(&item.leaf_index) {
                None => Grade::Unrun(format!(
                    "leaf {} has no authenticated envelope in this scope",
                    item.leaf_index
                )),
                Some(envelope) => graded(
                    &check_record(envelope, item.record, item.proposal_len)
                        .map_err(VerifyError::Record),
                ),
            },
        };
        let closure = if matches!(record, Grade::Pass) {
            closure_grade(item)
        } else {
            Grade::Unrun("the record did not verify".to_string())
        };
        checks.push(check("record", "inclusion", subject.clone(), record));
        checks.push(check("closure", "provenance", subject, closure));
        for stub in &item.stubs {
            checks.push(check(
                "public_commitment",
                "document",
                format!(
                    "document {} of leaf {} ({})",
                    hex(&stub.doc_commit),
                    item.leaf_index,
                    if stub.inline.is_some() {
                        "included"
                    } else {
                        "not included"
                    }
                ),
                public_commitment_grade(stub),
            ));
        }
    }

    for (k, b) in p.balances.iter().enumerate() {
        let subject = format!("balance {k}");
        let grade = match &signed {
            None => Grade::Unrun(CHECKPOINT_UNRUN.to_string()),
            Some(_) if (b.domain, b.version) != (FOLD_DOMAIN, FOLD_VERSION) => Grade::Fail(
                VerifyError::FoldLaw {
                    domain: b.domain.to_vec(),
                    version: b.version,
                }
                .to_string(),
            ),
            Some(s) => graded(&verify_balance(b.proof, &s.checkpoint)),
        };
        checks.push(check("recomputation", "recomputation", subject, grade));
    }

    let receipt = receipt.map(|bytes| receipt_grade(bytes, &digest, trusted_keys));
    if let Some(r) = &receipt {
        checks.push(check(
            "production_receipt",
            "production",
            "the detached production receipt".to_string(),
            match r {
                Ok(_) => Grade::Pass,
                Err(why) => Grade::Fail(why.clone()),
            },
        ));
    }

    Ok(BundleReport {
        digest,
        manifest: p.manifest,
        summary,
        checks,
        receipt: receipt.and_then(Result::ok),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_are_the_proleptic_gregorian_calendar() {
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(-1), "1969-12-31");
        assert_eq!(civil(59), "1970-03-01");
        assert_eq!(civil(11_016), "2000-02-29");
        assert_eq!(civil(20_454), "2026-01-01");
        assert_eq!(civil(-719_468), "0000-03-01");
    }

    #[test]
    fn each_scope_admits_exactly_one_completeness_claim() {
        assert_eq!(
            BundleScope::Prefix.admissible(7),
            Completeness::SeqRangeComplete { from: 0, to: 7 }
        );
        let account = BundleScope::Account(ScopeClaim {
            account: 1,
            from: 0,
            to: 1,
        });
        assert_eq!(account.admissible(7), Completeness::ScopeIndexComplete);
        let named = BundleScope::Entries(vec![2]);
        assert_eq!(named.admissible(7), Completeness::FilterAttested);
        assert_eq!(named.admissible(7).label(), "membership_only");
    }

    #[test]
    fn a_bundle_of_another_format_or_version_is_refused_before_anything_else() {
        assert_eq!(
            verify_bundle(b"", &[], None).unwrap_err(),
            BundleError::Format
        );
        let mut v2 = Vec::new();
        v2.extend_from_slice(&(BUNDLE_FORMAT.len() as u32).to_le_bytes());
        v2.extend_from_slice(BUNDLE_FORMAT);
        v2.extend_from_slice(&2u16.to_le_bytes());
        v2.extend_from_slice(&0u16.to_le_bytes());
        let e = verify_bundle(&v2, &[], None).unwrap_err();
        assert_eq!(e, BundleError::Version { major: 2, minor: 0 });
        assert!(e.to_string().contains("implements 1.0 only"), "{e}");
        let mut v1_1 = v2.clone();
        v1_1.truncate(v1_1.len() - 4);
        v1_1.extend_from_slice(&1u16.to_le_bytes());
        v1_1.extend_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            verify_bundle(&v1_1, &[], None).unwrap_err(),
            BundleError::Version { major: 1, minor: 1 }
        );
    }

    #[test]
    fn an_unimplemented_fold_law_names_both_laws() {
        let e = VerifyError::FoldLaw {
            domain: b"fa:register-fold:v3".to_vec(),
            version: 3,
        }
        .to_string();
        assert!(e.contains("`fa:register-fold:v3` version 3"), "{e}");
        assert!(e.contains("`fa:register-fold:v2` version 2 only"), "{e}");
    }
}
