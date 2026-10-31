//! Approvals in an evidence bundle (format 1.1; plan §14.5 non-repudiation,
//! Appendix A `Approval` and `signature`, FA-INV-10, bead fa-kae).
//!
//! ```text
//! bundle 1.1 = bundle 1.0 through list(balance)
//!            ‖ list(bytes(approval record)), strictly ascending by the identity each derives
//!            ‖ list(key leaf), strictly ascending by leaf_index
//!            ‖ bytes(manifest_md)
//! key leaf   = leaf_index u64 ‖ bytes(LeafEnvelope) ‖ list([32] accumulator path)
//!            ‖ proposal_len u32 ‖ bytes(record)
//!
//! approval record = body                                   (version 1: unsigned)
//!                 | u16 2 ‖ bytes(body) ‖ u16 scheme ‖ u32 generation ‖ [32] key_id ‖ [64] signature
//! body            = u16 1 ‖ [16] book ‖ u128 principal ‖ u8 profile ‖ [32] capability_commitment
//!                 ‖ [32] approved_proposal_digest ‖ u64 epoch ‖ u8 op ‖ u16 role
//! approval digest = BLAKE3("fa:approval:v1" ‖ u32 len ‖ body)
//! approval vid    = the first 16 bytes, little-endian, of
//!                   BLAKE3("fa:vid:approval:v1" ‖ book ‖ principal ‖ approved digest ‖ epoch)
//! signed message  = "fa:approval-signature:v1" ‖ approval digest
//!
//! key record      = u16 1 ‖ [16] book ‖ u128 principal ‖ u32 generation ‖ u16 scheme (1)
//!                 ‖ [32] public_key ‖ [64] possession ‖ opt [64] endorsement
//!                   (the canonical bytes of a PolicyControl SchemaChange of kind 24)
//! registration    = "fa:principal-key-registration:v1" ‖ BLAKE3("fa:principal-key-registration:v1"
//!                   ‖ each of book, principal, generation, scheme, public_key as u32 len ‖ bytes)
//! key_id          = BLAKE3("fa:principal-key-id:v1" ‖ u32 32 ‖ public_key)
//! ```
//!
//! A producer writes format 1.1 exactly when its in-scope entries cite an
//! approval. The bundle then carries the stored record of each approval
//! they cite, and, for each principal with a signed approval among them,
//! that principal's key generations in the checkpoint's prefix.
//!
//! What passes:
//! - every approval an in-scope entry cites is present, derives the cited
//!   identity, names the bundle's book, and approves that entry's own
//!   proposal digest (FA-INV-10), and no record is uncited;
//! - each key generation is an included PolicyControl principal-key record
//!   whose principal reference is the key's principal;
//! - each chain runs from generation 0 without a gap, every generation
//!   proves possession, and each later one is endorsed by the one before;
//! - a signed approval's signature is its named generation's Ed25519
//!   signature of the approval's digest.
//!
//! No claim:
//! - A signature proves possession of the key, not that a person pressed it.
//! - The approval's own recorded sequence is not authenticated here. So the
//!   bundle cannot show which generation was current when the kernel
//!   admitted the approval (the kernel checks that at commit), that an
//!   unsigned approval predates its principal's key, or that the bundle
//!   lists every later generation.
//! - The approval's profile, op, role and capability commitment are not
//!   judged; nor is whether the approver's capability allowed it, which the
//!   kernel decided at commit.

use std::collections::{BTreeMap, BTreeSet};

use super::{BundleCheck, CHECKPOINT_UNRUN, Grade, check};
use crate::blake3::{hash_parts, hex};
use crate::checkpoint::SignedCheckpoint;
use crate::codec::{DecodeError, Reader, Reason};
use crate::ed25519;
use crate::envelope::{KIND_ENTRY, LeafEnvelope, MAX_RECORD_BYTES, check_record};
use crate::proof::{MAX_ENVELOPE_BYTES, VerifyError, read_path, within};
use crate::tree::{Digest, leaf_hash, root_from_inclusion};

const APPROVAL_DOMAIN: &[u8] = b"fa:approval:v1";
const APPROVAL_VID_DOMAIN: &[u8] = b"fa:vid:approval:v1";
const APPROVAL_SIGNATURE_DOMAIN: &[u8] = b"fa:approval-signature:v1";
const KEY_ID_DOMAIN: &[u8] = b"fa:principal-key-id:v1";
const REGISTRATION_DOMAIN: &[u8] = b"fa:principal-key-registration:v1";
const SCHEME_ED25519: u16 = 1;
const BODY_VERSION: u16 = 1;
const SIGNED_VERSION: u16 = 2;
const KEY_VERSION: u16 = 1;
/// A version-1 approval body is exactly this long.
const BODY_BYTES: usize = 2 + 16 + 16 + 1 + 32 + 32 + 8 + 1 + 2;
/// A signed record: version, framed body, scheme, generation, key id,
/// signature.
const SIGNED_BYTES: usize = 2 + 4 + BODY_BYTES + 2 + 4 + 32 + 64;
/// The kernel walks at most this many generations of one chain.
const MAX_KEY_GENERATIONS: usize = 64;
const MAX_APPROVALS: usize = 1 << 20;
const MAX_KEY_LEAVES: usize = 1 << 16;

/// A principal-key generation's record, included under the checkpoint.
pub(super) struct KeyLeaf<'a> {
    pub leaf_index: u64,
    pub envelope: &'a [u8],
    pub path: Vec<Digest>,
    pub proposal_len: usize,
    pub record: &'a [u8],
}

/// The approval records of a 1.1 bundle, in file order.
pub(super) fn read_approvals<'a>(r: &mut Reader<'a>) -> Result<Vec<&'a [u8]>, DecodeError> {
    let n = r.count(MAX_APPROVALS, 4 + BODY_BYTES, "bundle.approvals")?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.bytes(SIGNED_BYTES, "approval.record")?);
    }
    Ok(out)
}

/// The key leaves of a 1.1 bundle, strictly ascending by leaf index.
pub(super) fn read_key_leaves<'a>(r: &mut Reader<'a>) -> Result<Vec<KeyLeaf<'a>>, DecodeError> {
    let n = r.count(MAX_KEY_LEAVES, 8 + 4 + 4 + 4 + 4, "bundle.key_leaves")?;
    let mut out: Vec<KeyLeaf<'a>> = Vec::with_capacity(n);
    for _ in 0..n {
        let leaf_index = r.u64("key_leaf.leaf_index")?;
        let envelope = r.bytes(MAX_ENVELOPE_BYTES, "key_leaf.envelope")?;
        let path = read_path(r)?;
        let proposal_len = usize::try_from(r.u32("key_leaf.proposal_len")?).unwrap_or(usize::MAX);
        let record = r.bytes(MAX_RECORD_BYTES, "key_leaf.record")?;
        if out.last().is_some_and(|k| k.leaf_index >= leaf_index) {
            return Err(r.error("bundle.key_leaves", Reason::Unsorted));
        }
        out.push(KeyLeaf {
            leaf_index,
            envelope,
            path,
            proposal_len,
            record,
        });
    }
    Ok(out)
}

/// Whether a stored approval record is the signed (version 2) form.
pub(super) fn is_signed(record: &[u8]) -> bool {
    record.get(..2) == Some(&SIGNED_VERSION.to_le_bytes()[..])
}

/// `BLAKE3(domain ‖ (u32 len ‖ part)...)`, fa-model's `domain_digest`.
fn framed(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut framed: Vec<u8> = Vec::new();
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(part);
    }
    hash_parts(domain, &[&framed])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApprovalSignature {
    pub scheme: u16,
    pub generation: u32,
    pub key_id: Digest,
    pub bytes: [u8; 64],
}

/// A stored approval record, read independently of the producer. Its
/// profile, op, role and capability commitment are read past, not judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApprovalRecord {
    pub book_id: [u8; 16],
    pub principal: u128,
    pub approved_digest: Digest,
    pub epoch: u64,
    /// What the identity and the signature are computed over.
    pub digest: Digest,
    pub signature: Option<ApprovalSignature>,
}

impl ApprovalRecord {
    pub(crate) fn decode(record: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(record);
        if r.u16("approval.version")? != SIGNED_VERSION {
            return decode_body(record);
        }
        let mut approval = decode_body(r.bytes(BODY_BYTES, "approval.body")?)?;
        approval.signature = Some(ApprovalSignature {
            scheme: r.u16("approval.signature.scheme")?,
            generation: r.u32("approval.signature.generation")?,
            key_id: r.fixed("approval.signature.key_id")?,
            bytes: r.fixed("approval.signature.bytes")?,
        });
        r.finish("approval record")?;
        Ok(approval)
    }

    /// The vertex identity the kernel derives from the approval's content.
    pub(crate) fn vid(&self) -> u128 {
        let d = hash_parts(
            APPROVAL_VID_DOMAIN,
            &[
                &self.book_id,
                &self.principal.to_le_bytes(),
                &self.approved_digest,
                &self.epoch.to_le_bytes(),
            ],
        );
        let mut lo = [0u8; 16];
        lo.copy_from_slice(&d[..16]);
        u128::from_le_bytes(lo)
    }
}

fn decode_body(body: &[u8]) -> Result<ApprovalRecord, DecodeError> {
    let mut r = Reader::new(body);
    let version = r.u16("approval.version")?;
    if version != BODY_VERSION {
        return Err(r.error("approval.version", Reason::BadTag(version.to_le_bytes()[0])));
    }
    let book_id = r.fixed("approval.book_id")?;
    let principal = r.u128("approval.principal")?;
    r.u8("approval.profile")?;
    r.fixed::<32>("approval.capability_commitment")?;
    let approved_digest = r.fixed("approval.approved_proposal_digest")?;
    let epoch = r.u64("approval.security_policy_epoch")?;
    r.u8("approval.op")?;
    r.u16("approval.role")?;
    r.finish("approval body")?;
    Ok(ApprovalRecord {
        book_id,
        principal,
        approved_digest,
        epoch,
        digest: framed(APPROVAL_DOMAIN, &[body]),
        signature: None,
    })
}

/// One generation of a principal's key chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyGeneration {
    pub book_id: [u8; 16],
    pub principal: u128,
    pub generation: u32,
    pub public_key: [u8; 32],
    pub possession: [u8; 64],
    pub endorsement: Option<[u8; 64]>,
}

impl KeyGeneration {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u16("principal_key.version")?;
        if version != KEY_VERSION {
            return Err(r.error(
                "principal_key.version",
                Reason::BadTag(version.to_le_bytes()[0]),
            ));
        }
        let book_id = r.fixed("principal_key.book_id")?;
        let principal = r.u128("principal_key.principal")?;
        let generation = r.u32("principal_key.generation")?;
        let scheme = r.u16("principal_key.scheme")?;
        if scheme != SCHEME_ED25519 {
            return Err(r.error(
                "principal_key.scheme",
                Reason::BadTag(scheme.to_le_bytes()[0]),
            ));
        }
        let public_key = r.fixed("principal_key.public_key")?;
        let possession = r.fixed("principal_key.possession")?;
        let endorsement = if r.present("principal_key.endorsement")? {
            Some(r.fixed("principal_key.endorsement")?)
        } else {
            None
        };
        r.finish("principal key")?;
        Ok(Self {
            book_id,
            principal,
            generation,
            public_key,
            possession,
            endorsement,
        })
    }

    pub(crate) fn key_id(&self) -> Digest {
        framed(KEY_ID_DOMAIN, &[&self.public_key])
    }

    /// The statement this generation's possession proof and endorsement
    /// sign.
    pub(crate) fn registration(&self) -> Vec<u8> {
        let mut message = REGISTRATION_DOMAIN.to_vec();
        message.extend_from_slice(&framed(
            REGISTRATION_DOMAIN,
            &[
                &self.book_id,
                &self.principal.to_le_bytes(),
                &self.generation.to_le_bytes(),
                &SCHEME_ED25519.to_le_bytes(),
                &self.public_key,
            ],
        ));
        message
    }
}

/// The approvals one authenticated in-scope entry cites.
pub(super) struct Citing {
    pub leaf_index: u64,
    pub proposal_digest: Digest,
    /// `(approval vid, approved digest)`, in the entry's order.
    pub approvals: Vec<(u128, Digest)>,
}

const CITATIONS_UNRUN: &str =
    "an in-scope entry's record did not verify, so its citations are unauthenticated";
const KEYS_UNRUN: &str = "a key record did not verify";

/// The approval checks of a 1.1 bundle. `citing` is `None` unless every
/// in-scope record verified.
pub(super) fn approval_checks(
    book_id: &[u8; 16],
    signed: Option<&SignedCheckpoint>,
    citing: Option<&[Citing]>,
    records: &[&[u8]],
    key_leaves: &[KeyLeaf<'_>],
) -> Vec<BundleCheck> {
    let mut checks = Vec::new();

    let decoded: Vec<Result<ApprovalRecord, DecodeError>> = records
        .iter()
        .copied()
        .map(ApprovalRecord::decode)
        .collect();
    checks.push(check(
        "approvals",
        "provenance",
        "the approvals the in-scope entries cite".to_string(),
        match citing {
            None => Grade::Unrun(CITATIONS_UNRUN.to_string()),
            Some(citing) => set_grade(book_id, citing, &decoded),
        },
    ));

    let mut chains: BTreeMap<u128, Vec<KeyGeneration>> = BTreeMap::new();
    let mut keys_verified = true;
    for leaf in key_leaves {
        let grade = match signed {
            None => Grade::Unrun(CHECKPOINT_UNRUN.to_string()),
            Some(s) => match key_leaf(book_id, s, leaf) {
                Ok(key) => {
                    chains.entry(key.principal).or_default().push(key);
                    Grade::Pass
                }
                Err(why) => Grade::Fail(why),
            },
        };
        keys_verified &= matches!(grade, Grade::Pass);
        checks.push(check(
            "key_record",
            "inclusion",
            format!("key leaf {}", leaf.leaf_index),
            grade,
        ));
    }

    let needed: Vec<u128> = decoded
        .iter()
        .filter_map(|a| a.as_ref().ok())
        .filter(|a| a.signature.is_some())
        .map(|a| a.principal)
        .collect();
    let mut current: BTreeMap<u128, &[KeyGeneration]> = BTreeMap::new();
    for (principal, chain) in &chains {
        let grade = if !keys_verified {
            Grade::Unrun(KEYS_UNRUN.to_string())
        } else if !needed.contains(principal) {
            Grade::Fail(
                "no signed approval in this bundle names this principal (a padded key chain)"
                    .to_string(),
            )
        } else {
            match chain_grade(chain) {
                Ok(()) => {
                    current.insert(*principal, chain);
                    Grade::Pass
                }
                Err(why) => Grade::Fail(why),
            }
        };
        checks.push(check(
            "key_chain",
            "signature",
            format!(
                "principal {principal:032x}, {} key generation(s)",
                chain.len()
            ),
            grade,
        ));
    }

    for (k, approval) in decoded.iter().enumerate() {
        let Ok(approval) = approval else {
            checks.push(check(
                "approval",
                "signature",
                format!("approval record {k}"),
                Grade::Unrun("the record does not decode".to_string()),
            ));
            continue;
        };
        let subject = format!(
            "approval {:032x} by principal {:032x}",
            approval.vid(),
            approval.principal
        );
        let (subject, grade) = match &approval.signature {
            None => (format!("{subject}: unsigned"), Grade::Pass),
            Some(signature) => {
                let chain = current.get(&approval.principal).copied();
                let grade = signature_grade(approval, signature, chain, keys_verified, &chains);
                (
                    format!(
                        "{subject}: signed by key generation {}",
                        signature.generation
                    ),
                    grade,
                )
            }
        };
        checks.push(check("approval", "signature", subject, grade));
    }
    checks
}

/// Every cited approval present and binding its citing entry's proposal;
/// no record uncited; records strictly ascending by identity.
fn set_grade(
    book_id: &[u8; 16],
    citing: &[Citing],
    decoded: &[Result<ApprovalRecord, DecodeError>],
) -> Grade {
    let mut by_vid: BTreeMap<u128, &ApprovalRecord> = BTreeMap::new();
    let mut previous: Option<u128> = None;
    for (k, approval) in decoded.iter().enumerate() {
        let approval = match approval {
            Ok(a) => a,
            Err(e) => return Grade::Fail(format!("approval record {k}: {e}")),
        };
        if approval.book_id != *book_id {
            return Grade::Fail(format!(
                "approval record {k} names book {}, not the bundle's {}",
                hex(&approval.book_id),
                hex(book_id)
            ));
        }
        let vid = approval.vid();
        if previous.is_some_and(|p| p >= vid) {
            return Grade::Fail(format!(
                "approval record {k} is not in strictly ascending identity order"
            ));
        }
        previous = Some(vid);
        by_vid.insert(vid, approval);
    }
    let mut cited: BTreeSet<u128> = BTreeSet::new();
    for entry in citing {
        for (vid, digest) in &entry.approvals {
            if *digest != entry.proposal_digest {
                return Grade::Fail(format!(
                    "leaf {} cites approval {vid:032x} of proposal {}, not its own proposal {} (FA-INV-10)",
                    entry.leaf_index,
                    hex(digest),
                    hex(&entry.proposal_digest)
                ));
            }
            let Some(approval) = by_vid.get(vid) else {
                return Grade::Fail(format!(
                    "leaf {} cites approval {vid:032x} and the bundle carries no record of it (an omitted approval)",
                    entry.leaf_index
                ));
            };
            if approval.approved_digest != *digest {
                return Grade::Fail(format!(
                    "approval {vid:032x} approves {}, not the proposal leaf {} cites it for",
                    hex(&approval.approved_digest),
                    entry.leaf_index
                ));
            }
            cited.insert(*vid);
        }
    }
    if let Some(extra) = by_vid.keys().find(|v| !cited.contains(v)) {
        return Grade::Fail(format!(
            "approval {extra:032x} is not cited by any in-scope entry (a padded approval)"
        ));
    }
    Grade::Pass
}

/// A key leaf's generation, after its inclusion, its record and its
/// principal-key control are checked.
fn key_leaf(
    book_id: &[u8; 16],
    signed: &SignedCheckpoint,
    leaf: &KeyLeaf<'_>,
) -> Result<KeyGeneration, String> {
    let cp = &signed.checkpoint;
    let envelope = LeafEnvelope::decode(leaf.envelope).map_err(|e| e.to_string())?;
    within(&envelope, cp).map_err(|e| e.to_string())?;
    if root_from_inclusion(
        leaf.leaf_index,
        cp.leaf_count,
        &leaf_hash(leaf.envelope),
        &leaf.path,
    ) != Some(cp.root)
    {
        return Err(VerifyError::Inclusion.to_string());
    }
    if envelope.kind != KIND_ENTRY {
        return Err(format!("leaf {} is not a journal entry", leaf.leaf_index));
    }
    check_record(&envelope, leaf.record, leaf.proposal_len)
        .map_err(|e| VerifyError::Record(e).to_string())?;
    let proposal = leaf.record.get(..leaf.proposal_len).unwrap_or_default();
    let Some(control) =
        crate::envelope::principal_key_control(proposal).map_err(|e| e.to_string())?
    else {
        return Err(format!(
            "leaf {} is not a principal-key control (PolicyControl, SchemaChange kind 24)",
            leaf.leaf_index
        ));
    };
    let key = KeyGeneration::decode(control.canonical).map_err(|e| e.to_string())?;
    if key.book_id != *book_id {
        return Err(format!(
            "the key names book {}, not the bundle's {}",
            hex(&key.book_id),
            hex(book_id)
        ));
    }
    if key.principal != control.principal_ref {
        return Err(format!(
            "the key is principal {:032x}'s, but principal {:032x} recorded it",
            key.principal, control.principal_ref
        ));
    }
    Ok(key)
}

/// Generations 0..n in leaf order, each proving possession and each after
/// the first endorsed by the one before.
fn chain_grade(chain: &[KeyGeneration]) -> Result<(), String> {
    if chain.len() > MAX_KEY_GENERATIONS {
        return Err(format!(
            "{} generations exceed the {MAX_KEY_GENERATIONS}-generation bound",
            chain.len()
        ));
    }
    let mut previous: Option<&KeyGeneration> = None;
    for (expected, key) in (0u32..).zip(chain) {
        if key.generation != expected {
            return Err(format!(
                "in leaf order, generation {} stands where generation {expected} belongs",
                key.generation
            ));
        }
        let message = key.registration();
        ed25519::verify(&key.public_key, &message, &key.possession).map_err(|e| {
            format!(
                "generation {expected}'s possession proof is not its key's signature of its registration: {e}"
            )
        })?;
        match (previous, &key.endorsement) {
            (None, None) => {}
            (Some(before), Some(endorsement)) => {
                ed25519::verify(&before.public_key, &message, endorsement).map_err(|e| {
                    format!(
                        "generation {expected} is not endorsed by generation {}'s key: {e}",
                        before.generation
                    )
                })?;
            }
            (None, Some(_)) => return Err("generation 0 carries an endorsement".to_string()),
            (Some(_), None) => {
                return Err(format!("generation {expected} carries no endorsement"));
            }
        }
        previous = Some(key);
    }
    Ok(())
}

/// Digest equality without an early exit. Key ids are public, so this only
/// keeps one comparison shape for everything a signature names.
fn same_digest(a: &Digest, b: &Digest) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn signature_grade(
    approval: &ApprovalRecord,
    signature: &ApprovalSignature,
    chain: Option<&[KeyGeneration]>,
    keys_verified: bool,
    supplied: &BTreeMap<u128, Vec<KeyGeneration>>,
) -> Grade {
    if !matches!(signature.scheme, SCHEME_ED25519) {
        return Grade::Fail(format!(
            "signature scheme {} is not Ed25519 (1)",
            signature.scheme
        ));
    }
    let Some(chain) = chain else {
        return if !keys_verified || supplied.contains_key(&approval.principal) {
            Grade::Unrun("the principal's key chain did not verify".to_string())
        } else {
            Grade::Fail("the bundle carries no key chain for the approving principal".to_string())
        };
    };
    let Some(key) = usize::try_from(signature.generation)
        .ok()
        .and_then(|g| chain.get(g))
    else {
        return Grade::Fail(format!(
            "the signature names key generation {}; the bundle's chain holds {}",
            signature.generation,
            chain.len()
        ));
    };
    if !same_digest(&key.key_id(), &signature.key_id) {
        return Grade::Fail(format!(
            "the signature names key {}, not generation {}'s key {}",
            hex(&signature.key_id),
            signature.generation,
            hex(&key.key_id())
        ));
    }
    let mut message = APPROVAL_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&approval.digest);
    match ed25519::verify(&key.public_key, &message, &signature.bytes) {
        Ok(()) => Grade::Pass,
        Err(e) => Grade::Fail(format!(
            "the signature is not generation {}'s signature of this approval's digest: {e}",
            signature.generation
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOK: [u8; 16] = [7; 16];

    /// An unsigned (version 1) record approving `digest` by `principal`.
    fn record(book: [u8; 16], principal: u128, digest: Digest) -> Vec<u8> {
        let mut r = Vec::with_capacity(BODY_BYTES);
        r.extend_from_slice(&BODY_VERSION.to_le_bytes());
        r.extend_from_slice(&book);
        r.extend_from_slice(&principal.to_le_bytes());
        r.push(1); // profile
        r.extend_from_slice(&[3; 32]); // capability commitment
        r.extend_from_slice(&digest);
        r.extend_from_slice(&0u64.to_le_bytes()); // epoch
        r.push(2); // op
        r.extend_from_slice(&0u16.to_le_bytes()); // role
        assert_eq!(r.len(), BODY_BYTES);
        r
    }

    fn citing(leaf_index: u64, proposal: Digest, cites: &[&ApprovalRecord]) -> Citing {
        Citing {
            leaf_index,
            proposal_digest: proposal,
            approvals: cites.iter().map(|a| (a.vid(), a.approved_digest)).collect(),
        }
    }

    fn grade(citing: &[Citing], records: &[&[u8]]) -> Grade {
        let decoded: Vec<_> = records
            .iter()
            .copied()
            .map(ApprovalRecord::decode)
            .collect();
        set_grade(&BOOK, citing, &decoded)
    }

    fn failed(g: &Grade, what: &str) {
        assert!(
            matches!(g, Grade::Fail(why) if why.contains(what)),
            "expected a failure naming {what:?}, got {g:?}"
        );
    }

    /// The set check: every citation has its record, binds its entry's own
    /// proposal and names the bundle's book; no record is uncited; records
    /// ascend by identity. Each planted defect is named.
    #[test]
    fn the_approval_set_is_exactly_the_cited_one_and_binds_each_entrys_proposal() {
        let (p1, p2) = ([1u8; 32], [2u8; 32]);
        let (r1, r2) = (record(BOOK, 10, p1), record(BOOK, 11, p2));
        let (a1, a2) = (
            ApprovalRecord::decode(&r1).unwrap(),
            ApprovalRecord::decode(&r2).unwrap(),
        );
        assert!(a1.signature.is_none());
        assert_eq!(
            a1.digest,
            framed(APPROVAL_DOMAIN, &[&r1]),
            "the digest is fa-model's framed digest of the body"
        );
        let mut ordered = [(a1.vid(), &r1[..]), (a2.vid(), &r2[..])];
        ordered.sort();
        let sorted: Vec<&[u8]> = ordered.iter().map(|(_, r)| *r).collect();
        let both = [citing(4, p1, &[&a1]), citing(9, p2, &[&a2])];
        assert_eq!(grade(&both, &sorted), Grade::Pass);

        // Omitted, padded and unsorted records.
        failed(&grade(&both, &sorted[..1]), "an omitted approval");
        let only_first = [citing(4, p1, &[&a1])];
        failed(&grade(&only_first, &sorted), "a padded approval");
        let reversed: Vec<&[u8]> = sorted.iter().rev().copied().collect();
        failed(&grade(&both, &reversed), "strictly ascending");
        // An entry citing an approval of another proposal (FA-INV-10).
        failed(
            &grade(&[citing(4, p2, &[&a1])], &[&r1[..]]),
            "not its own proposal",
        );
        // A record of another book.
        let foreign = record([8; 16], 10, p1);
        failed(&grade(&both, &[&foreign[..]]), "names book");
        // A record that does not decode is named by position.
        failed(&grade(&both, &[&r1[..r1.len() - 1]]), "approval record 0");
    }

    /// A key record decodes only under the Ed25519 scheme, its key id is the
    /// framed digest of its public key, and a possession proof that is not
    /// the key's signature fails the chain by name.
    #[test]
    fn key_records_name_the_scheme_and_key_ids_are_framed() {
        let mut k = Vec::new();
        k.extend_from_slice(&KEY_VERSION.to_le_bytes());
        k.extend_from_slice(&BOOK);
        k.extend_from_slice(&5u128.to_le_bytes());
        k.extend_from_slice(&0u32.to_le_bytes());
        k.extend_from_slice(&SCHEME_ED25519.to_le_bytes());
        k.extend_from_slice(&[9; 32]);
        k.extend_from_slice(&[0; 64]);
        k.push(0);
        let key = KeyGeneration::decode(&k).unwrap();
        assert_eq!(key.generation, 0);
        assert_eq!(key.endorsement, None);
        assert_eq!(key.key_id(), framed(KEY_ID_DOMAIN, &[&[9u8; 32]]));
        let mut other_scheme = k.clone();
        other_scheme[2 + 16 + 16 + 4] = 2;
        assert!(KeyGeneration::decode(&other_scheme).is_err());
        assert!(KeyGeneration::decode(&k[..k.len() - 1]).is_err());
        let why = chain_grade(&[key]).unwrap_err();
        assert!(why.contains("possession proof"), "{why}");
    }
}
