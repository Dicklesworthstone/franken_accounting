//! Attestation signatures over a complete prefix (plan §14.5, bead fa-kae).
//!
//! A complete prefix with its records (`fa:acc-prefix-proof:v2`)
//! authenticates every leaf, its payload and its position, so key chains and
//! attestations are read in commit order, as the kernel admitted them:
//! - Each principal-key control (a PolicyControl entry carrying a
//!   SchemaChange of kind 24) extends its principal's chain. The chain runs
//!   from generation 0 without a gap, each generation proving possession and
//!   each later one endorsed by the one before. The control must be recorded
//!   by the key's own principal.
//! - Each attestation is judged against its principal's chain as it stands
//!   at the attestation's position. With no key yet it must be unsigned
//!   (trailer scheme 0). With a key it must be signed (scheme 1) by the
//!   then-current generation: it names that generation and its key id, and
//!   carries that key's Ed25519 signature of
//!   `"fa:attestation-signature:v1" ‖ signed_digest`.
//!
//! This re-checks FA-REF-206 outside the kernel: no keyed principal's
//! attestation is unsigned or signed by a key that was not then current.
//!
//! No claim:
//! - A signature proves possession of the key, not that a person pressed it.
//! - Approvals are not journal leaves: their signatures are checked from
//!   bundles ([`crate::bundle`]), not here.

use std::collections::BTreeMap;

use crate::blake3::hex;
use crate::ed25519;
use crate::envelope::{KIND_ATTESTATION, KIND_ENTRY, attestation_auth, principal_key_control};
use crate::principal_keys::{KeyGeneration, attestation_message, same_digest};
use crate::proof::production::derivation::{LeafRecord, complete_records};
use crate::proof::{Checkpoint, VerifyError};

/// What a complete prefix's signature check covered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttestationSignatures {
    pub attestations: u64,
    /// Attestations under scheme 1, each verified.
    pub signed: u64,
    /// Principals with at least one key generation in the prefix.
    pub keyed_principals: u64,
    pub key_generations: u64,
}

/// Verify `proof` as a complete prefix with its records against `anchor`
/// (exactly as [`crate::proof::production::derivation::verify_prefix_with_records`]
/// does for the v2 format), then every key chain and attestation signature
/// in it. `Err` when the prefix itself does not verify; `Ok(Err(why))`
/// when it does but a chain or an attestation breaks the signature law,
/// `why` naming the leaf.
pub fn verify_attestation_signatures(
    proof: &[u8],
    anchor: &Checkpoint,
) -> Result<Result<AttestationSignatures, String>, VerifyError> {
    let records = complete_records(proof, anchor)?;
    let mut chains: BTreeMap<u128, Vec<KeyGeneration>> = BTreeMap::new();
    let mut report = AttestationSignatures::default();
    for (
        leaf,
        LeafRecord {
            envelope,
            payload,
            split,
        },
    ) in records.iter().enumerate()
    {
        let Some(proposal) = payload.get(..*split) else {
            return Err(VerifyError::Record(crate::envelope::RecordError::Split));
        };
        if envelope.kind == KIND_ENTRY {
            let Some(control) = principal_key_control(proposal)? else {
                continue;
            };
            let key = match KeyGeneration::decode(control.canonical) {
                Ok(key) => key,
                Err(e) => return Ok(Err(format!("leaf {leaf}: the principal key: {e}"))),
            };
            if key.book_id != envelope.book_id || key.principal != control.principal_ref {
                return Ok(Err(format!(
                    "leaf {leaf}: the key is not principal {:032x}'s own registration in this book",
                    control.principal_ref
                )));
            }
            let chain = chains.entry(key.principal).or_default();
            if let Err(why) = key.admit(chain.last(), chain.len()) {
                return Ok(Err(format!(
                    "leaf {leaf}: principal {:032x}'s key chain: {why}",
                    key.principal
                )));
            }
            chain.push(key);
            report.key_generations += 1;
        } else if envelope.kind == KIND_ATTESTATION {
            let auth = attestation_auth(payload, *split, envelope).map_err(VerifyError::Record)?;
            report.attestations += 1;
            let current = chains.get(&auth.principal).and_then(|chain| chain.last());
            match (current, &auth.signature) {
                (None, None) => {}
                (None, Some(_)) => {
                    return Ok(Err(format!(
                        "leaf {leaf}: a signed attestation by principal {:032x}, which had no registered key",
                        auth.principal
                    )));
                }
                (Some(key), None) => {
                    return Ok(Err(format!(
                        "leaf {leaf}: an unsigned attestation by principal {:032x}, whose key generation {} was current (FA-REF-206)",
                        auth.principal, key.generation
                    )));
                }
                (Some(key), Some(signature)) => {
                    let (named, named_key) = (signature.generation, signature.key_id);
                    if named != key.generation || !same_digest(&named_key, &key.key_id()) {
                        return Ok(Err(format!(
                            "leaf {leaf}: the attestation names key generation {named} ({}); generation {} was current",
                            hex(&named_key),
                            key.generation
                        )));
                    }
                    let message = attestation_message(&auth.signed_digest);
                    if let Err(e) = ed25519::verify(&key.public_key, &message, &signature.bytes) {
                        return Ok(Err(format!(
                            "leaf {leaf}: the attestation's signature is not generation {}'s signature of its digest: {e}",
                            key.generation
                        )));
                    }
                    report.signed += 1;
                }
            }
        }
    }
    report.keyed_principals = chains.len() as u64;
    Ok(Ok(report))
}
