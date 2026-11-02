//! Authenticate the recorded definition activation and its reviewed chart.
//!
//! The caller has already authenticated the complete checkpoint prefix and
//! derived every envelope from its payload. Approval references are part of
//! those immutable payloads; Approval object bodies and their historical
//! births are not. This module therefore proves the recorded control and
//! chart binding, never Human profiles, separation of duties, approval
//! admission, or the definition object's atomic birth.

use super::super::{ReportError, failed, metadata};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};
use crate::envelope::{
    KIND_ENTRY, LeafEnvelope, MAX_ENVELOPE_LIST, entry_approvals, proposal_after_legs,
};
use std::collections::BTreeSet;

const SCHEMA_CONTROL: u16 = 17;
const POLICY_CONTROL: u16 = 18;
const STATEMENT_ACTIVATION_REASON: u16 = 0x5354;
const CHART_DOMAIN: &[u8] = b"fa:statement-chart-basis:v1";
const DEFINITION_ID_DOMAIN: &[u8] = b"fa:vid:statement-definition:v1";

/// Facts independently bound by the complete authenticated entry prefix.
/// The cited references do not authenticate the uncommitted Approval rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCustomActivation {
    pub activation: u128,
    pub activated_at: u64,
    pub effective_from: i32,
    pub chart_digest: [u8; 32],
    /// Distinct recorded Approval identities and the proposal digests they cite.
    /// Distinct identities do not establish distinct Human approvers.
    pub approval_refs: Vec<(u128, [u8; 32])>,
    /// Always false: the prefix does not authenticate Approval-row birth,
    /// Human/profile status, policy epoch, or separation-of-duties admission.
    pub approval_admission_verified: bool,
    /// Always false: the definition's content is bound, but its database row's
    /// original birth and atomic publication with activation are not proved.
    pub definition_birth_verified: bool,
}

pub(super) struct ActivationSelection {
    pub activation: u128,
    pub activated_at: u64,
    pub definition_digest: [u8; 32],
    pub current_cutoff: i32,
}

fn invalid(message: impl Into<String>) -> ReportError {
    failed("custom_statement_activation", message)
}

fn definition_id(book: &[u8; 16], digest: &[u8; 32]) -> u128 {
    let mut parts = Writer::default();
    parts.bytes(book).bytes(digest);
    let digest = hash_parts(DEFINITION_ID_DOMAIN, &[&parts.buf]);
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(low)
}

/// Decode the precisely registered activation shape after the common metadata
/// decoder has checked the complete proposal. Book-scoped envelope dates are
/// absent; the activation's applicability date is in the committed proposal.
fn activation_fields(
    proposal: &[u8],
    book: &[u8; 16],
    definition_digest: &[u8; 32],
) -> Result<(i32, [u8; 32]), ReportError> {
    let mut prefix = Reader::new(proposal);
    prefix.u16("activation.major")?;
    prefix.u16("activation.minor")?;
    prefix.fixed::<16>("activation.book")?;
    prefix.fixed::<16>("activation.branch")?;
    prefix.u16("activation.class")?;
    let effective_from = prefix.i32("activation.effective_from")?;

    let mut r = proposal_after_legs(proposal)?;
    if !r.present("activation.control")?
        || r.u8("activation.control_tag")? != 3
        || r.u128("activation.definition")? != definition_id(book, definition_digest)
        || r.u8("activation.from")? != 0
        || r.u8("activation.to")? != 1
        || r.count(1, 33, "activation.chart_proofs")? != 1
        || r.u8("activation.chart_proof_tag")? != 1
    {
        return Err(invalid(
            "activation must transition the exact definition from 0 to 1 with one Object chart proof",
        ));
    }
    let chart_digest = r.fixed("activation.chart_digest")?;
    if r.u16("activation.reason")? != STATEMENT_ACTIVATION_REASON
        || r.count(0, 36, "activation.unit_totals")? != 0
        || r.present("activation.base_totals")?
    {
        return Err(invalid(
            "activation has an unrelated reason or monetary totals",
        ));
    }
    if r.bytes(64, "activation.key")?.is_empty()
        || r.u8("activation.origin")? != 3
        || r.u16("activation.control_kind")? != 3
        || r.fixed::<32>("activation.definition_digest")? != *definition_digest
    {
        return Err(invalid(
            "activation requires its original intent key and a definition-bound PolicyActivation origin",
        ));
    }
    r.u128("activation.principal")?;
    if r.present("activation.session")? {
        r.u128("activation.session")?;
    }
    let evidence = r.count(MAX_ENVELOPE_LIST, 65, "activation.evidence")?;
    for _ in 0..evidence {
        r.fixed::<65>("activation.evidence_ref")?;
    }
    let supersession = r.count(MAX_ENVELOPE_LIST, 51, "activation.supersession")?;
    for _ in 0..supersession {
        r.fixed::<51>("activation.supersession_ref")?;
    }
    if r.present("activation.pending")? {
        return Err(invalid(
            "an activation control cannot carry a pending block",
        ));
    }
    // metadata::entry_info has already consumed and checked the remainder,
    // including bounded tags and additive-minor extensions.
    Ok((effective_from, chart_digest))
}

/// Verify a pinned activation, including the original chart before its commit.
/// Later activations of the same name never replace this explicit selection.
/// The returned schema is for the caller's complete definition-partition lint;
/// report-column chart lint remains a separate required check.
pub(super) fn verify(
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    book: &[u8; 16],
    known_at: u64,
    selection: &ActivationSelection,
) -> Result<(VerifiedCustomActivation, metadata::Schema), ReportError> {
    if selection.activated_at == 0 || selection.activated_at > known_at {
        return Err(invalid(
            "activation is outside the selected recorded prefix",
        ));
    }
    if envelopes.len() != records.len() {
        return Err(invalid(
            "activation verification requires every prefix payload",
        ));
    }
    let mut selected = None;
    let mut controls = Vec::new();
    let mut schema_identities = BTreeSet::new();
    for (envelope, (len, payload)) in envelopes.iter().zip(records) {
        if envelope.kind != KIND_ENTRY || envelope.commit_seq > known_at {
            continue;
        }
        if envelope.book_id != *book || envelope.branch_id != [0; 16] {
            return Err(invalid(
                "activation history belongs to another book or branch",
            ));
        }
        let proposal = payload
            .get(..*len)
            .ok_or_else(|| invalid("activation history has a truncated proposal"))?;
        let info = metadata::entry_info(proposal, envelope)?;
        if info.matches_identity(selection.activation) {
            if selected.is_some()
                || envelope.class != POLICY_CONTROL
                || envelope.commit_seq != selection.activated_at
            {
                return Err(invalid(
                    "the activation identity is repeated, rebound, or recorded at another sequence",
                ));
            }
            let (effective_from, chart_digest) =
                activation_fields(proposal, book, &selection.definition_digest)?;
            if effective_from > selection.current_cutoff {
                return Err(invalid(
                    "the pinned activation is not effective at the current column cutoff",
                ));
            }
            let (proposal_digest, approval_refs) =
                entry_approvals(payload, *len).map_err(|error| invalid(format!("{error:?}")))?;
            let mut identities = BTreeSet::new();
            if approval_refs.len() < 2
                || approval_refs.iter().any(|(identity, approved)| {
                    *approved != proposal_digest || !identities.insert(*identity)
                })
            {
                return Err(invalid(
                    "activation must cite at least two distinct approvals bound to its exact proposal",
                ));
            }
            selected = Some(VerifiedCustomActivation {
                activation: selection.activation,
                activated_at: selection.activated_at,
                effective_from,
                chart_digest,
                approval_refs,
                approval_admission_verified: false,
                definition_birth_verified: false,
            });
        }
        if envelope.class == SCHEMA_CONTROL && envelope.commit_seq < selection.activated_at {
            let (kind, body) = info
                .schema
                .ok_or_else(|| invalid("reviewed chart contains a malformed SchemaControl"))?;
            if !schema_identities.insert(info.identity) {
                return Err(invalid(
                    "reviewed chart repeats an immutable schema identity",
                ));
            }
            controls.push((
                envelope.commit_seq,
                info.identity,
                envelope.record_digest,
                kind,
                body,
            ));
        }
    }
    let selected = selected.ok_or_else(|| {
        invalid("the cited activation does not exist in the selected authenticated prefix")
    })?;
    controls.sort_by_key(|(seq, identity, ..)| (*seq, *identity));
    let mut basis = Writer::default();
    basis.fixed(book).count(controls.len());
    let mut schema = metadata::Schema::default();
    for (seq, identity, digest, kind, body) in controls {
        basis.u64(seq).u128(identity).fixed(&digest);
        schema.apply(kind, body, book, seq)?;
    }
    // fa_model::domain_digest prefixes each part with its u32 byte length.
    let mut framed = Writer::default();
    framed.bytes(&basis.buf);
    if hash_parts(CHART_DOMAIN, &[&framed.buf]) != selected.chart_digest {
        return Err(invalid(
            "activation chart proof differs from the complete original schema history before activation",
        ));
    }
    Ok((selected, schema))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};

    const BOOK: [u8; 16] = [3; 16];
    const PRINCIPAL: u128 = 7;
    const DEFINITION: [u8; 32] = [9; 32];

    #[derive(Clone)]
    struct Record {
        proposal: Vec<u8>,
        payload: Vec<u8>,
        envelope: LeafEnvelope,
    }

    fn identity(key: &[u8]) -> u128 {
        let mut w = Writer::default();
        w.bytes(&BOOK).bytes(&PRINCIPAL.to_le_bytes()).bytes(key);
        let digest = hash_parts(b"fa:vid:entry:v1", &[&w.buf]);
        u128::from_le_bytes(digest[..16].try_into().unwrap())
    }

    fn proposal(
        class: u16,
        day: i32,
        key: &[u8],
        control: &[u8],
        origin_kind: u16,
        origin_digest: &[u8; 32],
    ) -> Vec<u8> {
        let mut w = Writer::default();
        w.u16(1)
            .u16(1)
            .fixed(&BOOK)
            .fixed(&[0; 16])
            .u16(class)
            .i32(day)
            .u8(0)
            .fixed(&[0; 32])
            .u8(0)
            .fixed(&[0; 24])
            .bytes(&[])
            .u8(0)
            .count(0)
            .u8(1)
            .fixed(control)
            .count(0)
            .u8(0)
            .bytes(key)
            .u8(3)
            .u16(origin_kind)
            .fixed(origin_digest)
            .u128(PRINCIPAL)
            .u8(0)
            .count(0)
            .count(0)
            .u8(0)
            .count(0)
            .count(0)
            .count(0);
        w.buf
    }

    fn seal(proposal: Vec<u8>, seq: u64, approvals: &[u128], bad_binding: bool) -> Record {
        let digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&proposal]);
        let mut acceptance = Writer::default();
        acceptance.u8(0).count(approvals.len());
        for (index, identity) in approvals.iter().enumerate() {
            let mut approved = digest;
            if index == 0 && bad_binding {
                approved[0] ^= 1;
            }
            acceptance.u128(*identity).fixed(&approved);
        }
        let record_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&digest, &acceptance.buf]);
        let mut payload = proposal.clone();
        payload.extend_from_slice(&acceptance.buf);
        payload.extend_from_slice(&digest);
        payload.extend_from_slice(&record_digest);
        let envelope = envelope_of_entry(&payload, proposal.len(), seq, 0).unwrap();
        Record {
            proposal,
            payload,
            envelope,
        }
    }

    fn chart(seq: u64, key: &[u8], code: &[u8]) -> Record {
        let mut body = Writer::default();
        body.count(1)
            .bytes(code)
            .bytes(b"Cash")
            .u8(1)
            .u8(0)
            .u8(1)
            .fixed(&1i64.to_le_bytes())
            .u8(0);
        let mut control = Writer::default();
        control.u8(1).u16(1).bytes(&body.buf);
        seal(
            proposal(17, 0, key, &control.buf, 1, &[0; 32]),
            seq,
            &[],
            false,
        )
    }

    fn reviewed_chart() -> (Vec<Record>, [u8; 32]) {
        let first = chart(1, b"chart", b"1000");
        // Non-account schema controls still belong to the reviewed chart basis.
        let mut control = Writer::default();
        control.u8(1).u16(5).bytes(&[]);
        let second = seal(
            proposal(17, 0, b"dimension", &control.buf, 1, &[0; 32]),
            2,
            &[],
            false,
        );
        let mut body = Writer::default();
        body.fixed(&BOOK)
            .count(2)
            .u64(1)
            .u128(identity(b"chart"))
            .fixed(&first.envelope.record_digest)
            .u64(2)
            .u128(identity(b"dimension"))
            .fixed(&second.envelope.record_digest);
        let digest = hash_parts(
            CHART_DOMAIN,
            &[&(body.buf.len() as u32).to_le_bytes(), &body.buf],
        );
        (vec![first, second], digest)
    }

    fn activation_control(chart_digest: &[u8; 32]) -> Vec<u8> {
        // Pin the producer's two-part domain framing independently of definition_id.
        let digest = hash_parts(
            DEFINITION_ID_DOMAIN,
            &[
                &16u32.to_le_bytes(),
                &BOOK,
                &32u32.to_le_bytes(),
                &DEFINITION,
            ],
        );
        let mut w = Writer::default();
        w.u8(3)
            .u128(u128::from_le_bytes(digest[..16].try_into().unwrap()))
            .u8(0)
            .u8(1)
            .count(1)
            .u8(1)
            .fixed(chart_digest)
            .u16(STATEMENT_ACTIVATION_REASON);
        w.buf
    }

    fn activation(control: &[u8], approvals: &[u128], bad_binding: bool) -> Record {
        seal(
            proposal(18, 10, b"activate", control, 3, &DEFINITION),
            4,
            approvals,
            bad_binding,
        )
    }

    fn selection() -> ActivationSelection {
        ActivationSelection {
            activation: identity(b"activate"),
            activated_at: 4,
            definition_digest: DEFINITION,
            current_cutoff: 30,
        }
    }

    fn verify_fixture(
        records: &[Record],
        known_at: u64,
        selected: &ActivationSelection,
    ) -> Result<(VerifiedCustomActivation, metadata::Schema), ReportError> {
        let envelopes: Vec<_> = records.iter().map(|r| r.envelope.clone()).collect();
        let payloads: Vec<_> = records
            .iter()
            .map(|r| (r.proposal.len(), r.payload.as_slice()))
            .collect();
        verify(&envelopes, &payloads, &BOOK, known_at, selected)
    }

    #[test]
    fn binds_definition_and_original_review_chart_without_claiming_human_admission() {
        let (mut records, chart_digest) = reviewed_chart();
        records.push(activation(
            &activation_control(&chart_digest),
            &[101, 102],
            false,
        ));
        records.push(chart(6, b"later-chart", b"1100"));
        let (verified, reviewed) = verify_fixture(&records, 6, &selection()).unwrap();
        assert_eq!(verified.activation, identity(b"activate"));
        assert_eq!(verified.activated_at, 4);
        assert_eq!(verified.effective_from, 10);
        assert_eq!(verified.chart_digest, chart_digest);
        assert_eq!(verified.approval_refs.len(), 2);
        assert!(!verified.approval_admission_verified);
        assert!(!verified.definition_birth_verified);
        assert_eq!(reviewed.accounts.len(), 1);
        assert_eq!(reviewed.accounts.values().next().unwrap().code, "1000");
    }

    #[test]
    fn refuses_resealed_activation_shape_and_definition_binding_changes() {
        let (prefix, chart_digest) = reviewed_chart();
        let original = activation_control(&chart_digest);
        // Every semantic field changes under a freshly resealed entry and
        // freshly proposal-bound approval references, not a broken outer hash.
        for offset in [0, 1, 17, 18, 19, 23, 24, 56] {
            let mut control = original.clone();
            control[offset] ^= 1;
            let mut records = prefix.clone();
            records.push(activation(&control, &[101, 102], false));
            assert!(
                verify_fixture(&records, 4, &selection()).is_err(),
                "offset {offset}"
            );
        }
        for (kind, definition) in [(1, DEFINITION), (3, [8; 32])] {
            let mut records = prefix.clone();
            records.push(seal(
                proposal(18, 10, b"activate", &original, kind, &definition),
                4,
                &[101, 102],
                false,
            ));
            assert!(verify_fixture(&records, 4, &selection()).is_err());
        }
    }

    #[test]
    fn refuses_missing_duplicate_and_rebound_approval_references() {
        let (prefix, chart_digest) = reviewed_chart();
        let control = activation_control(&chart_digest);
        for (references, bad_binding) in [
            (vec![], false),
            (vec![101], false),
            (vec![101, 101], false),
            (vec![101, 102], true),
        ] {
            let mut records = prefix.clone();
            records.push(activation(&control, &references, bad_binding));
            assert!(verify_fixture(&records, 4, &selection()).is_err());
        }
    }

    #[test]
    fn refuses_absent_rebound_or_future_activation_coordinates() {
        let (mut records, chart_digest) = reviewed_chart();
        assert!(verify_fixture(&records, 4, &selection()).is_err());
        records.push(activation(
            &activation_control(&chart_digest),
            &[101, 102],
            false,
        ));
        for selected in [
            ActivationSelection {
                activated_at: 0,
                ..selection()
            },
            ActivationSelection {
                activated_at: 3,
                ..selection()
            },
            ActivationSelection {
                activated_at: 5,
                ..selection()
            },
            ActivationSelection {
                activation: 42,
                ..selection()
            },
            ActivationSelection {
                definition_digest: [8; 32],
                ..selection()
            },
            ActivationSelection {
                current_cutoff: 9,
                ..selection()
            },
        ] {
            assert!(verify_fixture(&records, 4, &selected).is_err());
        }
        assert!(verify_fixture(&records, 3, &selection()).is_err());
        let duplicate = seal(records[2].proposal.clone(), 5, &[101, 102], false);
        records.push(duplicate);
        assert!(verify_fixture(&records, 5, &selection()).is_err());
        assert!(verify_fixture(&records, 4, &selection()).is_ok());
    }

    #[test]
    fn reviewed_chart_includes_non_account_controls_and_excludes_activation_commit() {
        let (mut records, chart_digest) = reviewed_chart();
        records.push(activation(
            &activation_control(&chart_digest),
            &[101, 102],
            false,
        ));
        // The review is at activated_at - 1, even for another schema member
        // sharing the activation's commit sequence.
        let mut same_commit = chart(4, b"same-commit-chart", b"1100");
        same_commit.envelope.within_commit_ordinal = 1;
        records.push(same_commit);
        let (_, reviewed) = verify_fixture(&records, 4, &selection()).unwrap();
        assert_eq!(reviewed.accounts.len(), 1);
        let without_non_account = vec![records[0].clone(), records[2].clone(), records[3].clone()];
        assert!(verify_fixture(&without_non_account, 4, &selection()).is_err());
        let mut changed = records.clone();
        changed[0] = chart(1, b"chart", b"1200");
        assert!(verify_fixture(&changed, 4, &selection()).is_err());
    }

    #[test]
    fn a_later_distinct_activation_does_not_replace_an_explicit_pinned_version() {
        let (mut records, chart_digest) = reviewed_chart();
        let control = activation_control(&chart_digest);
        records.push(activation(&control, &[101, 102], false));
        let later_definition = [8; 32];
        let later_id = hash_parts(
            DEFINITION_ID_DOMAIN,
            &[
                &16u32.to_le_bytes(),
                &BOOK,
                &32u32.to_le_bytes(),
                &later_definition,
            ],
        );
        let mut later_control = control.clone();
        later_control[1..17].copy_from_slice(&later_id[..16]);
        records.push(seal(
            proposal(
                18,
                20,
                b"later-activation",
                &later_control,
                3,
                &later_definition,
            ),
            6,
            &[201, 202],
            false,
        ));
        let (verified, _) = verify_fixture(&records, 6, &selection()).unwrap();
        assert_eq!(verified.activation, identity(b"activate"));
        assert_eq!(verified.effective_from, 10);
    }
}
