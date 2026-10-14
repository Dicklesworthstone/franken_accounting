//! Evidence bundles (`.fab`) and production receipts (plan §13.2,
//! Appendix A `Bundle` and `ProductionReceipt`), on the producer's side.
//!
//! ```text
//! bundle   = bytes("fa:bundle:v1") ‖ format_major u16 (1) ‖ format_minor u16 (0)
//!          ‖ manifest ‖ bytes(TransparencyCheckpoint) ‖ completeness proof
//!          ‖ list(entry) ‖ list(balance) ‖ bytes(manifest_md)
//! manifest = book_id [16] ‖ branch_id [16] ‖ through_seq u64 ‖ leaf_count u64
//!          ‖ checkpoint_oid [32]
//!          ‖ scope:        1 Prefix
//!                        | 2 Account  account u128 ‖ from i32 ‖ to i32
//!                        | 3 Entries  list(leaf_index u64), strictly ascending
//!          ‖ completeness: 1 SeqRangeComplete  from u64 (0) ‖ to u64 (leaf_count)
//!                        | 2 ScopeIndexComplete
//!                        | 3 FilterAttested
//! completeness proof = scope 1: bytes(PrefixProof)
//!                    | scope 2: bytes(ScopeProof)
//!                    | scope 3: list(bytes(LeafEnvelope) ‖ list([32] accumulator path))
//! entry    = leaf_index u64 ‖ proposal_len u32 ‖ bytes(record) ‖ list(stub),
//!            strictly ascending by leaf_index
//! stub     = doc_commit [32] ‖ kind u8 ‖ length u64 ‖ chunk_root [32]
//!            ‖ opt(bytes(document)), strictly ascending by doc_commit
//! balance  = bytes(fold_domain) ‖ fold_version u16 ‖ bytes(BalanceProof)
//!
//! bundle_digest  = BLAKE3("fa:bundle:v1" ‖ bundle)
//!
//! receipt  = body ‖ signer_key_id [32] ‖ scheme u16 ‖ bytes(signature)
//! body     = bytes("fa:production-receipt:v1") ‖ bundle_digest [32]
//!          ‖ producer_principal u128 ‖ produced_at_seq u64
//!          ‖ capability_commitment [32] ‖ opt([32] time_evidence_oid)
//! receipt_digest = BLAKE3("fa:production-receipt:v1" ‖ body)
//! signed message = "fa:production-receipt-signature:v1" ‖ receipt_digest
//! ```
//!
//! A bundle is a pure function of its request and the checkpoint it is
//! produced against: the same scope against the same checkpoint is the
//! same bytes, so two productions of the same material compare equal. Who
//! produced it, when, and under which capability live in the detached
//! [`ProductionReceipt`], which the book's key signs over the body's
//! digest. `fa-verify` reads both with its own decoder; the two are
//! independent implementations of this one layout, held together by the
//! differential tests and a golden vector.
//!
//! Each scope admits one completeness claim: the whole prefix is
//! `SeqRangeComplete(0, leaf_count)`, one account's effective-day
//! interval is `ScopeIndexComplete` (any other index scope is refused with
//! FA-REF-126), and named entries are `FilterAttested`, reported as
//! `membership_only`, never complete.
//!
//! A stub carries the document's chunk root beside its kind and length:
//! together they are exactly what `doc_commit` commits, so an outsider
//! checks every stub against its commitment whether or not the bytes are
//! included.
//!
//! Each cited document is read as the producing capability may see it
//! (plan §9.6, doctrine 8; the facade reads through
//! `fa_journal::read_document_for`, decided before any read of the bytes).
//! A document it sees only as a redacted view gets a stub the view proves,
//! without bytes; inlining one is refused (FA-REF-128), since version 1.0
//! inlines a whole document or none of its bytes and carries no view.
//!
//! Each balance is a balance-recomputation proof under the register fold
//! law it names ([`BALANCE_FOLD_DOMAIN`] version [`BALANCE_FOLD_VERSION`]),
//! so a later fold law cannot silently change what an older bundle's
//! balance claim means.
//!
//! Version 1.0 carries a subset of Appendix A's bundle, by name: closures
//! hold the documents each entry's own evidence list cites (no events,
//! rules, approvals, supplemental evidence or attestations); there are no
//! redacted views, register cells, statements, certificates or findings.
//! The receipt's `time_evidence_oid` is absent until TimeEvidence
//! is bound — a registered interim, as on the checkpoint.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_journal::{DocumentRead, KernelError};
use fa_model::{DecodeError, EncodeError, Entry, Oid, Reader, Writer};
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::checkpoint::{SignError, signer_key_id};
use crate::journal::Journal;
use crate::scope::{ScopeIndex, ScopeRequest};
use crate::sign::CheckpointSigner;
use crate::sign::ed25519::check_public_key;
use crate::state::StoredCheckpoint;
use crate::tree::Digest;
use crate::{code, scope};

pub const BUNDLE_FORMAT: &[u8] = b"fa:bundle:v1";
pub const BUNDLE_DIGEST_DOMAIN: &[u8] = b"fa:bundle:v1";
/// The fa-verify format a bundle targets.
pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 0;
pub const RECEIPT_FORMAT: &[u8] = b"fa:production-receipt:v1";
pub const RECEIPT_DIGEST_DOMAIN: &[u8] = b"fa:production-receipt:v1";
pub const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"fa:production-receipt-signature:v1";
/// The register fold law the balance proofs' claims are defined under:
/// posted debits and credits of (account, unit), holds excluded, through
/// an inclusive effective-day cutoff — the stock value the book's registers
/// fold under this domain (the tests pin it to `fa_registers`' own).
pub const BALANCE_FOLD_DOMAIN: &[u8] = b"fa:register-fold:v2";
pub const BALANCE_FOLD_VERSION: u16 = 2;

const SCOPE_PREFIX: u8 = 1;
const SCOPE_ACCOUNT: u8 = 2;
const SCOPE_ENTRIES: u8 = 3;
const COMPLETENESS_SEQ_RANGE: u8 = 1;
const COMPLETENESS_SCOPE_INDEX: u8 = 2;
const COMPLETENESS_FILTER_ATTESTED: u8 = 3;
const MAX_SIGNATURE_BYTES: usize = 1024;

fn hash(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().0
}

/// What a bundle covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleScope {
    /// Every leaf of the checkpoint's prefix (`SeqRangeComplete`).
    Prefix,
    /// A scope the index proves complete (`ScopeIndexComplete`): only an
    /// exact account's effective-day interval; the others are FA-REF-126.
    Index(ScopeRequest),
    /// Named entries, membership only (`FilterAttested`).
    Entries(Vec<VId>),
}

/// A balance to recompute: posted (debits, credits) of (account, unit)
/// through an inclusive effective-day cutoff, or every effective day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceRequest {
    pub account: VId,
    pub unit: u32,
    pub effective_through: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleRequest {
    pub scope: BundleScope,
    pub balances: Vec<BalanceRequest>,
    /// Include each cited document's bytes; otherwise its stub carries the
    /// commitment, kind and length only.
    pub inline_documents: bool,
}

/// A produced bundle: its canonical bytes and their digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub bytes: Vec<u8>,
    pub digest: Digest,
}

/// A cited document as a bundle lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentStub {
    pub doc_commit: [u8; 32],
    pub kind: u8,
    pub length: u64,
    /// The root of the document's 4 KiB chunk tree (plan §9.1).
    pub chunk_root: [u8; 32],
    pub inline: Option<Vec<u8>>,
}

/// `BLAKE3("fa:bundle:v1" ‖ bundle)`.
#[must_use]
pub fn bundle_digest(bundle: &[u8]) -> Digest {
    hash(BUNDLE_DIGEST_DOMAIN, &[bundle])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The civil date of a day count since 1970-01-01 (proleptic Gregorian).
fn civil(day: i32) -> String {
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

/// What the manifest says, in the form `manifest_md` restates it.
struct Manifest<'a> {
    book_id: [u8; 16],
    branch_id: [u8; 16],
    through_seq: u64,
    leaf_count: u64,
    checkpoint_oid: [u8; 32],
    scope: Scope<'a>,
}

enum Scope<'a> {
    Prefix,
    Account { account: u128, from: i32, to: i32 },
    Entries(&'a [u64]),
}

impl Manifest<'_> {
    fn encode(&self, w: &mut Writer) {
        w.fixed(&self.book_id)
            .fixed(&self.branch_id)
            .u64(self.through_seq)
            .u64(self.leaf_count)
            .fixed(&self.checkpoint_oid);
        match self.scope {
            Scope::Prefix => {
                w.u8(SCOPE_PREFIX)
                    .u8(COMPLETENESS_SEQ_RANGE)
                    .u64(0)
                    .u64(self.leaf_count);
            }
            Scope::Account { account, from, to } => {
                w.u8(SCOPE_ACCOUNT)
                    .u128(account)
                    .i32(from)
                    .i32(to)
                    .u8(COMPLETENESS_SCOPE_INDEX);
            }
            Scope::Entries(leaves) => {
                w.u8(SCOPE_ENTRIES)
                    .list(leaves, |w, i| {
                        w.u64(*i);
                    })
                    .u8(COMPLETENESS_FILTER_ATTESTED);
            }
        }
    }

    /// The text `fa-verify` regenerates and compares byte for byte.
    fn markdown(&self, entries: usize, documents: usize, inline: usize, balances: usize) -> String {
        let (scope, label, meaning) = match self.scope {
            Scope::Prefix => (
                "every leaf of the journal prefix".to_string(),
                "seq_range_complete",
                format!(
                    "leaves 0 to {}: every leaf is listed and recomputes the checkpoint's root",
                    self.leaf_count
                ),
            ),
            Scope::Account { account, from, to } => (
                format!(
                    "account {account:032x}, entries effective {} through {}",
                    civil(from),
                    civil(to)
                ),
                "scope_index_complete",
                "the account's entries in the interval are one gap-free run of the checkpoint's signed scope index".to_string(),
            ),
            Scope::Entries(leaves) => (
                format!("{} named journal leaves", leaves.len()),
                "membership_only",
                "each listed entry is in the journal; nothing is said about entries not listed"
                    .to_string(),
            ),
        };
        let laws = if balances == 0 {
            String::new()
        } else {
            format!(
                ", under register fold {} version {BALANCE_FOLD_VERSION}",
                String::from_utf8_lossy(BALANCE_FOLD_DOMAIN)
            )
        };
        format!(
            "# FrankenAccounting evidence bundle\n\
             \n\
             - Format: fa:bundle:v1, for fa-verify format {FORMAT_MAJOR}.{FORMAT_MINOR}\n\
             - Book: {}\n\
             - Branch: {}\n\
             - Known at: commit sequence {} ({} journal leaves)\n\
             - Checkpoint: {}\n\
             - Scope: {scope}\n\
             - Completeness: {label} ({meaning})\n\
             - Entries: {entries}, with their payloads\n\
             - Documents: {documents} cited, {inline} included\n\
             - Balances: {balances}{laws}\n\
             \n\
             Verify: fa-verify bundle <this file> --key <the book's checkpoint public key> [--receipt <its production receipt>]\n\
             \n\
             This text restates the manifest. It verifies nothing: fa-verify's report is the verification.\n",
            hex(&self.book_id),
            hex(&self.branch_id),
            self.through_seq,
            self.leaf_count,
            hex(&self.checkpoint_oid),
        )
    }
}

fn corrupt(what: impl Into<String>) -> KernelError {
    KernelError::Corrupt(what.into())
}

fn encode_failed(e: EncodeError) -> KernelError {
    KernelError::Model(fa_model::EntryError::Encode(e))
}

fn inline_withheld(oid: &Oid, contract: u16) -> Refusal {
    Refusal::new(
        code::INLINE_WITHHELD,
        exit::REFUSAL,
        format!(
            "document {} is governed by redaction contract {contract} and this capability reads only its redacted view: a v1 bundle inlines a whole document or none of its bytes",
            hex(&oid.0)
        ),
        "plan §9.6, §13.2 (a production discloses no more of a document than its capability may read)",
        "produce without inline documents (each stub still carries the commitment, kind, length and chunk root), or with a capability that also holds privileged",
    )
}

/// The standalone verifier's inline-document bound (`16 MiB`, matching
/// `registries/evidence_policy.toml` `max_document_bytes` and
/// `fa_verify::bundle::MAX_DOCUMENT_BYTES`).
pub const MAX_INLINE_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
/// The standalone verifier's balance-proof list bound (`4096`, matching
/// `fa_verify::bundle::MAX_BALANCES`).
pub const MAX_BUNDLE_BALANCES: usize = 4096;

/// Refusal when a bundle request exceeds [`MAX_BUNDLE_BALANCES`].
#[must_use]
pub fn balance_limit(count: usize) -> Refusal {
    Refusal::new(
        code::BUNDLE_LIMIT,
        exit::REFUSAL,
        format!(
            "bundle requests {count} balances, exceeding the standalone verifier's limit of {MAX_BUNDLE_BALANCES}"
        ),
        "plan §13.2, §13.3 (a bundle never signs an inline document or balance list the standalone verifier's bounds reject)",
        "produce without inline documents (each stub still carries the commitment, kind, length and chunk root) when a cited document exceeds 16 MiB, or split the balance requests across bundles of at most 4096 balances",
    )
}

/// Refusal when an inline document in a bundle exceeds [`MAX_INLINE_DOCUMENT_BYTES`].
#[must_use]
pub fn inline_document_limit(oid: &Oid, length: u64) -> Refusal {
    Refusal::new(
        code::BUNDLE_LIMIT,
        exit::REFUSAL,
        format!(
            "document {} is {length} bytes, exceeding the standalone verifier's inline document limit of {MAX_INLINE_DOCUMENT_BYTES} bytes",
            hex(&oid.0)
        ),
        "plan §13.2, §13.3 (a bundle never signs an inline document or balance list the standalone verifier's bounds reject)",
        "produce without inline documents (each stub still carries the commitment, kind, length and chunk root) when a cited document exceeds 16 MiB, or split the balance requests across bundles of at most 4096 balances",
    )
}

/// What an entry's evidence list cites, ascending by `doc_commit`, one
/// citation per document (one document cited in two roles is one stub).
fn citations(payload: &[u8]) -> Result<Vec<([u8; 32], Oid)>, KernelError> {
    let entry = Entry::decode(payload)?;
    let mut cited: Vec<([u8; 32], Oid)> = entry
        .proposal
        .evidence
        .iter()
        .map(|e| (e.doc_commit, e.document_oid))
        .collect();
    cited.sort();
    cited.dedup_by_key(|(commit, _)| *commit);
    Ok(cited)
}

/// The stubs of the documents an entry cites, from what the producing
/// capability read of each ([`cited_documents`]). A document read only as
/// its redacted view gives the stub the view proves, without bytes, and
/// cannot be inlined (FA-REF-128). An inline document over 16 MiB is refused
/// (FA-REF-129) before hashing or cloning so the producer never signs a
/// bundle the standalone verifier rejects.
fn stubs(
    payload: &[u8],
    inline: bool,
    documents: &BTreeMap<Oid, DocumentRead>,
) -> Outcome<Vec<DocumentStub>> {
    let cited = citations(payload)?;
    let mut out = Vec::with_capacity(cited.len());
    for (commit, oid) in cited {
        let Some(read) = documents.get(&oid) else {
            return Err(corrupt(format!(
                "cited document {} was not read for this bundle",
                hex(&oid.0)
            )));
        };
        out.push(match read {
            DocumentRead::Full(doc) => {
                if inline && doc.bytes.len() > MAX_INLINE_DOCUMENT_BYTES {
                    return Ok(Err(inline_document_limit(&oid, doc.bytes.len() as u64)));
                }
                DocumentStub {
                    doc_commit: commit,
                    kind: doc.kind,
                    length: doc.bytes.len() as u64,
                    chunk_root: fa_journal::evidence::chunk_root(&doc.bytes),
                    inline: inline.then(|| doc.bytes.clone()),
                }
            }
            DocumentRead::Redacted(view) if inline => {
                return Ok(Err(inline_withheld(&oid, view.contract)));
            }
            DocumentRead::Redacted(view) => DocumentStub {
                doc_commit: commit,
                kind: view.kind,
                length: view.size,
                chunk_root: view.chunk_root(),
                inline: None,
            },
        });
    }
    Ok(Ok(out))
}

fn not_in_prefix(vid: VId, through: CommitSeq) -> Refusal {
    Refusal::new(
        code::NOT_IN_PREFIX,
        exit::REFUSAL,
        format!(
            "entry {:032x} is not in the accumulator prefix through {}",
            vid.0, through.0
        ),
        "plan §13.1 (membership is proved only within an authenticated prefix)",
        "produce against a checkpoint published after the entry was recorded",
    )
}

/// The leaves a bundle's scope holds, ascending; the completeness proof of
/// that scope; and, for named entries, the named leaf indices.
struct InScope {
    indices: Vec<usize>,
    proof: Vec<u8>,
    leaves: Vec<u64>,
}

/// The scope `request` names over `journal`, or its refusal (FA-REF-129 when
/// `request.balances` exceeds 4096, FA-REF-126 for an index scope other than
/// one account, FA-REF-120 for a named entry outside the prefix).
fn in_scope(journal: &Journal, request: &BundleRequest) -> Outcome<InScope> {
    if request.balances.len() > MAX_BUNDLE_BALANCES {
        return Ok(Err(balance_limit(request.balances.len())));
    }
    let (indices, proof, leaves): (Vec<usize>, Vec<u8>, Vec<u64>) = match &request.scope {
        BundleScope::Prefix => (
            (0..journal.leaves.len()).collect(),
            journal.prefix_proof()?,
            Vec::new(),
        ),
        BundleScope::Index(req) => {
            let proof = match scope::prove(journal, req)? {
                Ok(p) => p,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let ScopeRequest::Account { account, from, to } = req else {
                return Err(corrupt("an index scope other than one account was proved"));
            };
            let index = ScopeIndex::of(journal);
            let (lo, hi) = index.range(account.0, *from, *to);
            let mut run: Vec<usize> = index
                .tuples()
                .get(lo..hi)
                .unwrap_or_default()
                .iter()
                .map(|t| usize::try_from(t.leaf_index).unwrap_or(usize::MAX))
                .collect();
            run.sort_unstable();
            (run, proof, Vec::new())
        }
        BundleScope::Entries(vids) => {
            let mut run = Vec::with_capacity(vids.len());
            for vid in vids {
                match journal.leaf_index(*vid) {
                    Some(i) => run.push(i),
                    None => return Ok(Err(not_in_prefix(*vid, journal.through_seq))),
                }
            }
            run.sort_unstable();
            run.dedup();
            let mut members: Vec<(&[u8], Vec<Digest>)> = Vec::with_capacity(run.len());
            for i in &run {
                let leaf = journal
                    .leaves
                    .get(*i)
                    .ok_or_else(|| corrupt("a named leaf outside the prefix"))?;
                let path = journal
                    .leaf_path(*i)
                    .ok_or_else(|| corrupt("inclusion path outside the tree"))?;
                members.push((leaf.envelope_bytes.as_slice(), path));
            }
            let mut w = Writer::with_capacity(256 * run.len());
            w.list(&members, |w, (envelope, path)| {
                w.bytes(envelope).list(path, |w, d| {
                    w.fixed(d);
                });
            });
            let leaves = run.iter().map(|i| *i as u64).collect();
            (run, w.finish().map_err(encode_failed)?, leaves)
        }
    };
    Ok(Ok(InScope {
        indices,
        proof,
        leaves,
    }))
}

/// The documents the bundle `request` asks for cites, each once, in the
/// order [`assemble`] stubs them: what the producer reads, as its
/// capability may see each one, before assembling (plan §9.6, doctrine 8).
/// The scope is refused here exactly as `assemble` refuses it, so nothing
/// is read for a bundle that cannot be produced.
pub fn cited_documents(journal: &Journal, request: &BundleRequest) -> Outcome<Vec<Oid>> {
    let scope = match in_scope(journal, request)? {
        Ok(scope) => scope,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for i in &scope.indices {
        let leaf = journal
            .leaves
            .get(*i)
            .ok_or_else(|| corrupt("an in-scope leaf outside the prefix"))?;
        for (_, oid) in citations(&leaf.payload)? {
            if seen.insert(oid) {
                out.push(oid);
            }
        }
    }
    Ok(Ok(out))
}

/// Assemble the bundle `request` asks for over `journal`, against the
/// checkpoint `checkpoint` stands for (the caller has recomputed both from
/// the journal; [`crate::bundle_basis`]). `documents` holds what the
/// producing capability read of each document [`cited_documents`] names.
pub fn assemble(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    request: &BundleRequest,
    documents: &BTreeMap<Oid, DocumentRead>,
) -> Outcome<Bundle> {
    assemble_with_runs(journal, checkpoint, request, documents, &BTreeMap::new())
}

/// [`assemble`], with the migration run bodies its balances need (read with
/// [`crate::migration_balance::bundle_run_bodies`]): a balance whose cell
/// selects migration candidates is proved in the migration-aware v2 format,
/// any other in v1, and a needed body that is absent is refused.
pub fn assemble_with_runs(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    request: &BundleRequest,
    documents: &BTreeMap<Oid, DocumentRead>,
    run_bodies: &BTreeMap<VId, fa_journal::migration::RunBody>,
) -> Outcome<Bundle> {
    let statement = journal.statement();
    if checkpoint.checkpoint.body.statement != statement {
        return Err(corrupt(
            "the checkpoint is not the journal prefix's statement",
        ));
    }
    let InScope {
        indices,
        proof,
        leaves,
    } = match in_scope(journal, request)? {
        Ok(scope) => scope,
        Err(refusal) => return Ok(Err(refusal)),
    };

    let mut entries = Vec::with_capacity(indices.len());
    for i in &indices {
        let leaf = journal
            .leaves
            .get(*i)
            .ok_or_else(|| corrupt("an in-scope leaf outside the prefix"))?;
        let proposal_len = u32::try_from(leaf.proposal_len)
            .map_err(|_| corrupt("proposal longer than u32::MAX bytes"))?;
        let stubs = match stubs(&leaf.payload, request.inline_documents, documents)? {
            Ok(stubs) => stubs,
            Err(refusal) => return Ok(Err(refusal)),
        };
        entries.push((*i as u64, proposal_len, &leaf.payload, stubs));
    }
    let mut balances = Vec::with_capacity(request.balances.len());
    for b in &request.balances {
        match journal.balance_proof_auto(b.account, b.unit, b.effective_through, run_bodies)? {
            Ok(proof) => balances.push(proof),
            Err(refusal) => return Ok(Err(refusal)),
        }
    }

    let scope = match &request.scope {
        BundleScope::Prefix => Scope::Prefix,
        BundleScope::Index(ScopeRequest::Account { account, from, to }) => Scope::Account {
            account: account.0,
            from: *from,
            to: *to,
        },
        BundleScope::Index(_) => {
            return Err(corrupt("an index scope other than one account was proved"));
        }
        BundleScope::Entries(_) => Scope::Entries(&leaves),
    };
    let manifest = Manifest {
        book_id: statement.book_id.0,
        branch_id: statement.branch_id.0,
        through_seq: statement.through_seq.0,
        leaf_count: statement.leaf_count,
        checkpoint_oid: checkpoint.oid.0,
        scope,
    };
    let documents: usize = entries.iter().map(|e| e.3.len()).sum();
    let inline = entries
        .iter()
        .flat_map(|e| &e.3)
        .filter(|s| s.inline.is_some())
        .count();
    let markdown = manifest.markdown(entries.len(), documents, inline, balances.len());

    let mut w = Writer::with_capacity(
        4096 + proof.len()
            + entries.iter().map(|e| e.2.len() + 64).sum::<usize>()
            + balances.iter().map(Vec::len).sum::<usize>(),
    );
    w.bytes(BUNDLE_FORMAT).u16(FORMAT_MAJOR).u16(FORMAT_MINOR);
    manifest.encode(&mut w);
    w.bytes(&checkpoint.bytes);
    match request.scope {
        BundleScope::Prefix | BundleScope::Index(_) => {
            w.bytes(&proof);
        }
        // The membership list is already in canonical list form.
        BundleScope::Entries(_) => {
            w.fixed(&proof);
        }
    }
    w.list(&entries, |w, (index, proposal_len, payload, stubs)| {
        w.u64(*index)
            .u32(*proposal_len)
            .bytes(payload)
            .list(stubs, |w, s| {
                w.fixed(&s.doc_commit)
                    .u8(s.kind)
                    .u64(s.length)
                    .fixed(&s.chunk_root)
                    .opt(s.inline.as_ref(), |w, bytes| {
                        w.bytes(bytes);
                    });
            });
    });
    w.list(&balances, |w, proof| {
        w.bytes(BALANCE_FOLD_DOMAIN)
            .u16(BALANCE_FOLD_VERSION)
            .bytes(proof);
    });
    w.str(&markdown);
    let bytes = w.finish().map_err(encode_failed)?;
    Ok(Ok(Bundle {
        digest: bundle_digest(&bytes),
        bytes,
    }))
}

/// The fields a production receipt signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptBody {
    pub bundle_digest: Digest,
    pub producer_principal: VId,
    pub produced_at_seq: CommitSeq,
    pub capability_commitment: [u8; 32],
    /// Absent until TimeEvidence is bound (a registered interim).
    pub time_evidence_oid: Option<Oid>,
}

impl ReceiptBody {
    fn encode(&self, w: &mut Writer) {
        w.bytes(RECEIPT_FORMAT)
            .fixed(&self.bundle_digest)
            .u128(self.producer_principal.0)
            .u64(self.produced_at_seq.0)
            .fixed(&self.capability_commitment)
            .opt(self.time_evidence_oid.as_ref(), |w, o| {
                w.fixed(&o.0);
            });
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::with_capacity(160);
        self.encode(&mut w);
        w.finish()
    }

    /// `"fa:production-receipt-signature:v1" ‖ BLAKE3("fa:production-receipt:v1" ‖ body)`.
    pub fn signed_message(&self) -> Result<Vec<u8>, EncodeError> {
        let mut m = RECEIPT_SIGNATURE_DOMAIN.to_vec();
        m.extend_from_slice(&hash(RECEIPT_DIGEST_DOMAIN, &[&self.canonical_bytes()?]));
        Ok(m)
    }
}

/// The detached receipt of one production: who produced which bundle, at
/// which recorded sequence, under which capability, signed by the book's
/// key. It travels beside the bundle, never inside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionReceipt {
    pub body: ReceiptBody,
    pub signer_key_id: [u8; 32],
    pub scheme: u16,
    pub signature: Vec<u8>,
}

impl ProductionReceipt {
    /// `body` signed by `signer`, after admitting its public key: one that
    /// is not a curve point or is a small-order point signs nothing.
    pub fn sign(body: ReceiptBody, signer: &dyn CheckpointSigner) -> Result<Self, SignError> {
        let key = signer.public_key();
        check_public_key(&key).map_err(|reason| SignError::UntrustableKey {
            signer_key_id: signer_key_id(&key),
            reason,
        })?;
        Ok(Self {
            signature: signer.sign(&body.signed_message()?).to_vec(),
            signer_key_id: signer_key_id(&key),
            scheme: signer.scheme(),
            body,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::with_capacity(256);
        self.body.encode(&mut w);
        w.fixed(&self.signer_key_id)
            .u16(self.scheme)
            .bytes(&self.signature);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.bytes(64, "receipt.format")? != RECEIPT_FORMAT {
            return Err(r.invalid("receipt.format"));
        }
        let body = ReceiptBody {
            bundle_digest: r.fixed("receipt.bundle_digest")?,
            producer_principal: VId(r.u128("receipt.producer_principal")?),
            produced_at_seq: CommitSeq(r.u64("receipt.produced_at_seq")?),
            capability_commitment: r.fixed("receipt.capability_commitment")?,
            time_evidence_oid: r.opt("receipt.time_evidence_oid", |r| {
                Ok(Oid(r.fixed("receipt.time_evidence_oid")?))
            })?,
        };
        let signer_key_id = r.fixed("receipt.signer_key_id")?;
        let scheme = r.u16("receipt.scheme")?;
        let signature = r.bytes(MAX_SIGNATURE_BYTES, "receipt.signature")?.to_vec();
        r.finish()?;
        Ok(Self {
            body,
            signer_key_id,
            scheme,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::SigningKey;

    #[test]
    fn civil_dates_are_the_proleptic_gregorian_calendar() {
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(-1), "1969-12-31");
        assert_eq!(civil(59), "1970-03-01");
        assert_eq!(civil(11_016), "2000-02-29");
        assert_eq!(civil(20_454), "2026-01-01");
        assert_eq!(civil(-719_468), "0000-03-01");
    }

    fn body() -> ReceiptBody {
        ReceiptBody {
            bundle_digest: [1; 32],
            producer_principal: VId(7),
            produced_at_seq: CommitSeq(41),
            capability_commitment: [2; 32],
            time_evidence_oid: None,
        }
    }

    /// Round trip; the signed message covers every body field and no
    /// signature field; a small-order signer key signs nothing.
    #[test]
    fn receipts_round_trip_bind_every_field_and_refuse_untrustable_keys() {
        let key = SigningKey::from_seed(&[9; 32]);
        let receipt = ProductionReceipt::sign(body(), &key).unwrap();
        let bytes = receipt.canonical_bytes().unwrap();
        assert_eq!(ProductionReceipt::decode(&bytes).unwrap(), receipt);
        let base = body().signed_message().unwrap();
        let mut variants = vec![body(); 5];
        variants[0].bundle_digest[0] ^= 1;
        variants[1].producer_principal = VId(8);
        variants[2].produced_at_seq = CommitSeq(42);
        variants[3].capability_commitment[31] ^= 1;
        variants[4].time_evidence_oid = Some(Oid([3; 32]));
        for v in &variants {
            assert_ne!(v.signed_message().unwrap(), base, "{v:?}");
        }
        let mut long = bytes.clone();
        long.push(0);
        assert!(ProductionReceipt::decode(&long).is_err());

        for t in crate::sign::ed25519::tests::torsion_encodings() {
            assert!(matches!(
                ProductionReceipt::sign(body(), &Fixed(t)),
                Err(SignError::UntrustableKey { .. })
            ));
        }
    }

    /// A signer that claims any public key and signs nothing real.
    struct Fixed([u8; 32]);

    impl CheckpointSigner for Fixed {
        fn scheme(&self) -> u16 {
            crate::sign::scheme::ED25519
        }
        fn public_key(&self) -> [u8; 32] {
            self.0
        }
        fn sign(&self, _: &[u8]) -> [u8; 64] {
            [0; 64]
        }
    }
}
