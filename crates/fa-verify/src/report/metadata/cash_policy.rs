//! Independent bounded transport of an approved cash-policy definition.
//!
//! Report math uses the exact policy carried by its certificate. These checks
//! authenticate the activation's shape and body commitment in the journal;
//! they do not claim to prove native approver authority or separation of duties.

use super::{Reader, ReportError, failed, framed_identity, text};
use crate::envelope::{LeafEnvelope, MAX_ENVELOPE_LIST, skip_erasable};

const FORMAT: &[u8] = b"fa:cash-flow-policy-definition:v1";
const MAX_BODY: usize = 64 * 1024;
const REASON: u16 = 0x4346;

/// Called after the generic lifecycle tag has been consumed. Other lifecycle
/// reasons keep their existing interpretation; this only detects the reserved
/// cash-policy discriminator so its definition cannot be silently omitted.
pub(super) fn has_activation_reason(r: &mut Reader<'_>) -> Result<bool, ReportError> {
    r.u128("cash_policy.target")?;
    r.u8("cash_policy.from")?;
    r.u8("cash_policy.to")?;
    for _ in 0..r.count(MAX_ENVELOPE_LIST, 17, "cash_policy.proofs")? {
        match r.u8("cash_policy.proof_tag")? {
            0 => {
                r.u128("cash_policy.proof_vertex")?;
            }
            1 => {
                r.fixed::<32>("cash_policy.proof_object")?;
            }
            _ => {
                return Err(failed(
                    "cash_policy_history",
                    "unknown lifecycle proof reference",
                ));
            }
        }
    }
    Ok(r.u16("cash_policy.reason")? == REASON)
}

fn definition(bytes: &[u8]) -> Result<[u8; 32], ReportError> {
    let mut r = Reader::new(bytes);
    if bytes.len() > MAX_BODY || r.bytes(64, "cash_policy.format")? != FORMAT {
        return Err(failed(
            "cash_policy_history",
            "unsupported or oversized cash policy definition",
        ));
    }
    let name = text(&mut r, 64, "cash_policy.name")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || r.u32("cash_policy.version")? == 0
    {
        return Err(failed(
            "cash_policy_history",
            "cash policy name or version is invalid",
        ));
    }
    let count = r.count(4096, 16, "cash_policy.cash_accounts")?;
    if count == 0 {
        return Err(failed(
            "cash_policy_history",
            "cash policy requires cash accounts",
        ));
    }
    let mut cash = Vec::with_capacity(count);
    for _ in 0..count {
        let account = r.u128("cash_policy.cash_account")?;
        if cash.last().is_some_and(|previous| *previous >= account) {
            return Err(failed(
                "cash_policy_history",
                "cash policy cash accounts are not strictly ordered",
            ));
        }
        cash.push(account);
    }
    let count = r.count(4096, 17, "cash_policy.account_rules")?;
    let mut previous = None;
    for _ in 0..count {
        let account = r.u128("cash_policy.account")?;
        let activity = r.u8("cash_policy.activity")?;
        if previous.is_some_and(|previous| previous >= account)
            || cash.binary_search(&account).is_ok()
            || activity > 3
        {
            return Err(failed(
                "cash_policy_history",
                "cash policy rules must be ordered, disjoint from cash and use activity tags 0..3",
            ));
        }
        previous = Some(account);
    }
    r.finish("cash policy definition")?;
    Ok(crate::blake3::hash_parts(
        b"fa:cash-flow-policy-definition-digest:v1",
        &[&(bytes.len() as u32).to_le_bytes(), bytes],
    ))
}

pub(super) fn activation(
    proposal: &[u8],
    envelope: &LeafEnvelope,
    body: &[u8],
) -> Result<(), ReportError> {
    let digest = definition(body)?;
    let mut r = Reader::new(proposal);
    if r.u16("cash_policy.major")? != 1
        || r.u16("cash_policy.minor")? < 11
        || r.fixed::<16>("cash_policy.book")? != envelope.book_id
        || r.fixed::<16>("cash_policy.branch")? != [0; 16]
        || r.u16("cash_policy.class")? != 18
        || envelope.class != 18
    {
        return Err(failed(
            "cash_policy_history",
            "cash policy requires its own trunk PolicyControl at minor 11 or later",
        ));
    }
    r.i32("cash_policy.effective_from")?;
    if r.present("cash_policy.document_date")? {
        return Err(failed(
            "cash_policy_history",
            "cash policy activation has a document date",
        ));
    }
    skip_erasable(&mut r, "cash_policy.description")?;
    if r.present("cash_policy.period")?
        || r.u32("cash_policy.legs")? != 0
        || !r.present("cash_policy.control")?
        || r.u8("cash_policy.control_tag")? != 3
    {
        return Err(failed(
            "cash_policy_history",
            "cash policy activation must be a legless lifecycle control",
        ));
    }
    let target = r.u128("cash_policy.target")?;
    if r.u8("cash_policy.from")? != 0
        || r.u8("cash_policy.to")? != 1
        || r.u32("cash_policy.proofs")? != 1
        || r.u8("cash_policy.proof_tag")? != 1
    {
        return Err(failed(
            "cash_policy_history",
            "cash policy activation needs one chart digest proof",
        ));
    }
    r.fixed::<32>("cash_policy.chart_digest")?;
    if r.u16("cash_policy.reason")? != REASON
        || r.u32("cash_policy.unit_totals")? != 0
        || r.present("cash_policy.base_totals")?
    {
        return Err(failed(
            "cash_policy_history",
            "cash policy activation has an unrelated reason or monetary totals",
        ));
    }
    let key = r.bytes(64, "cash_policy.key")?;
    if key.is_empty()
        || r.u8("cash_policy.origin")? != 3
        || r.u16("cash_policy.control_kind")? != 3
        || r.fixed::<32>("cash_policy.definition_digest")? != digest
    {
        return Err(failed(
            "cash_policy_history",
            "cash policy origin does not bind its exact definition",
        ));
    }
    let principal = r.u128("cash_policy.principal")?;
    if target
        != framed_identity(
            b"fa:vid:entry:v1",
            &[&envelope.book_id, &principal.to_le_bytes(), key],
        )
        || r.present("cash_policy.session")?
        || r.u32("cash_policy.evidence")? != 0
        || r.u32("cash_policy.supersession")? != 0
        || r.present("cash_policy.pending")?
        || r.u32("cash_policy.external_ids")? != 0
        || r.u32("cash_policy.tags")? != 0
        || r.u32("cash_policy.extensions")? != 1
        || r.u16("cash_policy.extension_tag")? != 43
        || r.bytes(MAX_BODY, "cash_policy.definition")? != body
    {
        return Err(failed(
            "cash_policy_history",
            "cash policy activation target or exclusive body shape differs",
        ));
    }
    r.finish("cash policy activation")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;

    fn body(name: &[u8], version: u32, cash: &[u128], rules: &[(u128, u8)]) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(FORMAT).bytes(name).u32(version).count(cash.len());
        for account in cash {
            w.u128(*account);
        }
        w.count(rules.len());
        for (account, activity) in rules {
            w.u128(*account).u8(*activity);
        }
        w.buf
    }

    #[test]
    fn independent_cash_policy_decoder_checks_version_partition_and_exact_framing() {
        let bytes = body(
            b"company-cash",
            1,
            &[1, 2],
            &[(3, 0), (4, 1), (5, 2), (6, 3)],
        );
        assert!(definition(&bytes).is_ok());
        for end in 0..bytes.len() {
            assert!(definition(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(definition(&trailing).is_err());
        for malformed in [
            body(b"", 1, &[1], &[(2, 0)]),
            body(b"company cash", 1, &[1], &[(2, 0)]),
            body(b"company-cash", 0, &[1], &[(2, 0)]),
            body(b"company-cash", 1, &[], &[(2, 0)]),
            body(b"company-cash", 1, &[1, 1], &[(2, 0)]),
            body(b"company-cash", 1, &[1], &[(1, 0)]),
            body(b"company-cash", 1, &[1], &[(2, 4)]),
            body(b"company-cash", 1, &[1], &[(3, 0), (2, 0)]),
        ] {
            assert!(definition(&malformed).is_err());
        }
        assert_ne!(
            definition(&bytes).unwrap(),
            definition(&body(
                b"company-cash",
                2,
                &[1, 2],
                &[(3, 0), (4, 1), (5, 2), (6, 3)]
            ))
            .unwrap()
        );
    }

    #[test]
    fn independent_cash_policy_activation_binds_typed_body_origin_and_own_identity() {
        let body = body(b"company-cash", 1, &[1], &[(2, 0)]);
        let book = [7; 16];
        let key = b"cash-policy";
        let principal = 99u128;
        let target = framed_identity(b"fa:vid:entry:v1", &[&book, &principal.to_le_bytes(), key]);
        let mut w = Writer::default();
        w.u16(1)
            .u16(11)
            .fixed(&book)
            .fixed(&[0; 16])
            .u16(18)
            .i32(10)
            .u8(0);
        w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(b"");
        w.u8(0).count(0).u8(1).u8(3);
        let target_offset = w.buf.len();
        w.u128(target).u8(0).u8(1).count(1).u8(1).fixed(&[8; 32]);
        w.u16(REASON).count(0).u8(0).bytes(key).u8(3).u16(3);
        let digest_offset = w.buf.len();
        w.fixed(&definition(&body).unwrap())
            .u128(principal)
            .u8(0)
            .count(0)
            .count(0)
            .u8(0)
            .count(0)
            .count(0)
            .count(1);
        let tag_offset = w.buf.len();
        w.u16(43).bytes(&body);
        let proposal = w.buf;
        let envelope = LeafEnvelope {
            kind: 1,
            book_id: book,
            branch_id: [0; 16],
            commit_seq: 5,
            within_commit_ordinal: 0,
            record_digest: [0; 32],
            class: 18,
            effective_day: None,
            account_vids: vec![],
            unit_ids: vec![],
        };
        activation(&proposal, &envelope, &body).unwrap();
        for end in 0..proposal.len() {
            assert!(activation(&proposal[..end], &envelope, &body).is_err());
        }
        for offset in [2, target_offset, digest_offset, tag_offset] {
            let mut changed = proposal.clone();
            changed[offset] ^= 1;
            assert!(
                activation(&changed, &envelope, &body).is_err(),
                "offset {offset}"
            );
        }
        let mut wrong_class = envelope.clone();
        wrong_class.class = 17;
        assert!(activation(&proposal, &wrong_class, &body).is_err());
        let mut trailing = proposal.clone();
        trailing.push(0);
        assert!(activation(&trailing, &envelope, &body).is_err());
    }
}
