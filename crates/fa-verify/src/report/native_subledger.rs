//! Native AR/AP detail independently grouped from the authenticated journal.
//!
//! The source is a complete native stock trial balance. The outer certificate
//! adds one immutable subledger designation, historical party identities and
//! four gross columns per party/unit. This is accounting recomputation, not
//! external-feed completeness, economic truth, native graph-mirror integrity
//! or historical posting/approval admission. Sealed party names and identifiers
//! are structurally decoded; they are never decrypted or asserted authentic.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    MAX_REPORT_BUNDLE_BYTES, MAX_ROWS, ReportError, ReportRow, Selection, dimension, failed,
    hash_parts, metadata, text,
};
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg, proposal_leg_details};

const CERTIFICATE_FORMAT: &[u8] = b"fa:native-subledger-certificate:v1";
const CERTIFICATE_DIGEST: &[u8] = b"fa:native-subledger-certificate-digest:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:native-subledger-reconciliation:v1";
const DESIGNATION_FORMAT: &[u8] = b"fa:native-subledger:v1";
const PARTY_DIMENSION: u32 = 12;

/// A recipient-owned fixed accounting question. Never populate this request
/// by copying the untrusted certificate that is being verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSubledgerRequest {
    pub code: String,
    pub control_account: u128,
    pub effective_through: i32,
    pub known_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNativeSubledgerRow {
    pub party: u128,
    pub party_value: u128,
    pub party_code: String,
    pub unit: u32,
    pub debits: i128,
    pub credits: i128,
    pub debits_pending: i128,
    pub credits_pending: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNativeSubledgerTotal {
    pub unit: u32,
    pub detail_debits: i128,
    pub detail_credits: i128,
    pub detail_debits_pending: i128,
    pub detail_credits_pending: i128,
    pub control_debits: i128,
    pub control_credits: i128,
    pub control_debits_pending: i128,
    pub control_credits_pending: i128,
}

/// Complete native detail for the selected control at one recorded/effective
/// coordinate. Unused parties do not create rows; currencies are never summed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNativeSubledger {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub effective_through: i32,
    pub source_certificate_digest: [u8; 32],
    pub subledger_vid: u128,
    pub code: String,
    pub name: String,
    /// Native kind: 1 = receivables (Asset), 2 = payables (Liability).
    pub kind: u8,
    pub control_account: u128,
    pub declaration_entry_vid: u128,
    pub declaration_entry_digest: [u8; 32],
    pub declared_at: u64,
    /// Ordered by immutable party code, then native unit identifier.
    pub rows: Vec<VerifiedNativeSubledgerRow>,
    /// Ordered by native unit; all four columns are compared independently.
    pub totals: Vec<VerifiedNativeSubledgerTotal>,
    pub reconciled: bool,
}

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub request: NativeSubledgerRequest,
    pub registry_digest: [u8; 32],
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "native subledger certificate exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "native_subledger.format")? != CERTIFICATE_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported native subledger certificate",
        ));
    }
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "native_subledger.source")?;
    let request = NativeSubledgerRequest {
        code: text(&mut r, 64, "native_subledger.code")?.into(),
        control_account: r.u128("native_subledger.control_account")?,
        effective_through: r.i32("native_subledger.effective_through")?,
        known_at: r.u64("native_subledger.known_at")?,
    };
    if request.code.is_empty() {
        return Err(failed(
            "native_subledger_request",
            "subledger code is empty",
        ));
    }
    let registry_digest = r.fixed("native_subledger.registry_digest")?;
    // The certificate commits these producer assertions, but their native
    // authority is not an outsider proof and supplies no metadata or amounts.
    r.u128("native_subledger.producer")?;
    r.fixed::<32>("native_subledger.capability_commitment")?;
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "native_subledger.output")?;
    if !output.starts_with(OUTPUT_FORMAT) {
        return Err(failed(
            "supported_report",
            "unsupported native subledger output",
        ));
    }
    let digest = r.fixed("native_subledger.digest")?;
    r.finish("native subledger certificate")?;
    let body = &bytes[..bytes.len() - 32];
    if hash_parts(
        CERTIFICATE_DIGEST,
        &[&(body.len() as u32).to_le_bytes(), body],
    ) != digest
    {
        return Err(failed(
            "certificate_digest",
            "native subledger certificate commitment differs",
        ));
    }
    Ok(Certificate {
        source,
        request,
        registry_digest,
        output,
        digest,
    })
}

pub(super) fn bind_request(
    certificate: &Certificate<'_>,
    expected: &NativeSubledgerRequest,
) -> Result<(), ReportError> {
    if expected.code.is_empty() || expected.code.len() > 64 || &certificate.request != expected {
        return Err(failed(
            "native_subledger_request",
            "native subledger certificate differs from the recipient's fixed code, control account, cutoff or known-at",
        ));
    }
    Ok(())
}

pub(super) fn bind_source(
    certificate: &Certificate<'_>,
    source: &super::Certificate<'_>,
) -> Result<(), ReportError> {
    if !certificate.source.starts_with(super::CERTIFICATE_FORMAT)
        || source.known_at != certificate.request.known_at
        || source.selection != Selection::AsOf(certificate.request.effective_through)
        || source.branch != [0; 16]
        || source.time_selection.is_some()
        || source.dimension.is_some()
        || source.functional
    {
        return Err(failed(
            "native_subledger_request",
            "native subledger requires its complete sequence-selected trunk native v1 stock trial balance at the same cutoff and known-at",
        ));
    }
    Ok(())
}

fn metadata_error(detail: impl Into<String>) -> ReportError {
    failed("native_subledger_metadata", detail)
}

fn identity(domain: &[u8], parts: &[&[u8]]) -> u128 {
    let mut w = Writer::default();
    for part in parts {
        w.bytes(part);
    }
    let digest = hash_parts(domain, &[&w.buf]);
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(low)
}

/// Decode the complete erasable structure under the original 256-byte plain
/// value bound. The sealed representation adds salt32, length4 and tag16.
fn party_field(r: &mut Reader<'_>) -> Result<[u8; 32], ReportError> {
    let digest = r.fixed("party.field_digest")?;
    if r.present("party.subject")? {
        r.u128("party.subject")?;
    }
    r.fixed::<24>("party.nonce")?;
    r.bytes(256 + 32 + 4 + 16, "party.sealed")?;
    Ok(digest)
}

fn party_code(body: &[u8]) -> Result<String, ReportError> {
    let mut r = Reader::new(body);
    let code = text(&mut r, 64, "party.code")?.to_string();
    if code.is_empty() || !(1..=8).contains(&r.u8("party.kind")?) {
        return Err(metadata_error("invalid party code or kind"));
    }
    party_field(&mut r)?;
    let count = r.count(32, 65, "party.identifiers")?;
    let mut previous = None;
    for _ in 0..count {
        let key = text(&mut r, 64, "party.identifier.key")?;
        if key.is_empty() || previous.is_some_and(|value| value >= key) {
            return Err(metadata_error(
                "party identifier keys are empty, duplicated or unordered",
            ));
        }
        previous = Some(key);
        party_field(&mut r)?;
    }
    let count = r.count(256, 65, "party.external_ids")?;
    let mut previous = None;
    for _ in 0..count {
        let system = text(&mut r, 64, "party.external_id.system")?;
        let digest = party_field(&mut r)?;
        let key = (system, digest);
        if system.is_empty() || previous.is_some_and(|value| value >= key) {
            return Err(metadata_error(
                "party external IDs are empty, duplicated or unordered",
            ));
        }
        previous = Some(key);
    }
    r.finish("party declaration")?;
    Ok(code)
}

struct Designation {
    code: String,
    name: String,
    kind: u8,
    control: u128,
    entry: u128,
    digest: [u8; 32],
    recorded_at: u64,
}

fn designation(
    body: &[u8],
    entry: u128,
    envelope: &LeafEnvelope,
) -> Result<Designation, ReportError> {
    let mut r = Reader::new(body);
    if &r.fixed::<{ DESIGNATION_FORMAT.len() }>("subledger.designation_format")?
        != DESIGNATION_FORMAT
    {
        return Err(metadata_error("unsupported native subledger designation"));
    }
    let code = text(&mut r, 64, "subledger.code")?.to_string();
    let name = text(&mut r, 256, "subledger.name")?.to_string();
    let kind = r.u8("subledger.kind")?;
    let control = r.u128("subledger.control")?;
    r.finish("subledger designation")?;
    if code.is_empty() || name.is_empty() || !matches!(kind, 1 | 2) {
        return Err(metadata_error("invalid native subledger designation"));
    }
    Ok(Designation {
        code,
        name,
        kind,
        control,
        entry,
        digest: envelope.record_digest,
        recorded_at: envelope.commit_seq,
    })
}

fn add_columns(total: &mut [i128; 4], values: [i128; 4]) -> Result<(), ReportError> {
    for (sum, value) in total.iter_mut().zip(values) {
        if value < 0 {
            return Err(failed(
                "exact_arithmetic",
                "native subledger amount is negative",
            ));
        }
        *sum = sum
            .checked_add(value)
            .ok_or_else(|| failed("exact_arithmetic", "native subledger column overflow"))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    certificate: &Certificate<'_>,
    source: &super::Certificate<'_>,
    units: &[u32],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    visible_migrations: &BTreeSet<u64>,
    resolved: &BTreeSet<usize>,
    control_rows: &[ReportRow],
) -> Result<(VerifiedNativeSubledger, Vec<u8>), ReportError> {
    bind_source(certificate, source)?;
    let mut parties = BTreeMap::new();
    let mut party_identities = BTreeSet::new();
    let mut selected = None;
    for (&index, info) in infos {
        match info.schema {
            Some((5, body)) => {
                let code = party_code(body)?;
                let party = identity(b"fa:vid:party:v1", &[&source.book, code.as_bytes()]);
                let value = dimension::value_vid(&source.book, "party", &code);
                if !party_identities.insert(party) || parties.insert(value, (party, code)).is_some()
                {
                    return Err(metadata_error(
                        "duplicate party declaration or derived identity",
                    ));
                }
            }
            Some((15, body)) => {
                let declaration = designation(body, info.identity, &envelopes[index])?;
                if declaration.code == certificate.request.code {
                    if selected.replace(declaration).is_some() {
                        return Err(metadata_error("duplicate selected subledger declaration"));
                    }
                }
            }
            _ => {}
        }
    }
    let declaration =
        selected.ok_or_else(|| metadata_error("selected subledger is absent at known-at"))?;
    if declaration.control != certificate.request.control_account {
        return Err(metadata_error(
            "selected declaration names a different control account",
        ));
    }
    let account = schema
        .accounts
        .get(&declaration.control)
        .ok_or_else(|| metadata_error("selected control account is absent"))?;
    if !account.is_leaf || account.account_type != declaration.kind {
        return Err(metadata_error(
            "native subledger control must be its designated Asset or Liability posting leaf",
        ));
    }
    if control_rows
        .iter()
        .any(|row| units.binary_search(&row.unit).is_err())
    {
        return Err(failed(
            "registry_closure",
            "native source contains an unregistered unit",
        ));
    }
    let mut detail: BTreeMap<(u128, u32), [i128; 4]> = BTreeMap::new();
    for &index in infos.keys() {
        let envelope = &envelopes[index];
        if (envelope.class == 2 && resolved.contains(&index))
            || (envelope.class == 12 && !visible_migrations.contains(&(index as u64)))
            || !legs[index]
                .iter()
                .any(|leg| leg.account == declaration.control)
        {
            continue;
        }
        let effective = envelope
            .effective_day
            .ok_or_else(|| metadata_error("monetary entry lacks an effective date"))?;
        if effective > certificate.request.effective_through {
            continue;
        }
        let (len, payload) = records[index];
        let details = proposal_leg_details(&payload[..len])?;
        if details.len() != legs[index].len() {
            return Err(metadata_error("party and monetary leg counts differ"));
        }
        for (leg, details) in legs[index].iter().zip(details) {
            if leg.account != declaration.control {
                continue;
            }
            let value = details
                .dimensions
                .iter()
                .find(|(kind, _)| *kind == PARTY_DIMENSION)
                .map(|(_, value)| *value)
                .ok_or_else(|| metadata_error("native subledger leg has no party attribution"))?;
            if !parties.contains_key(&value) {
                return Err(metadata_error(
                    "native subledger leg names an undeclared party value",
                ));
            }
            if leg.mantissa < 0 {
                return Err(failed(
                    "exact_arithmetic",
                    "native subledger leg is negative",
                ));
            }
            let columns = detail.entry((value, leg.unit)).or_insert([0; 4]);
            let column = usize::from(!leg.debit) + if envelope.class == 2 { 2 } else { 0 };
            columns[column] = columns[column]
                .checked_add(leg.mantissa)
                .ok_or_else(|| failed("exact_arithmetic", "native subledger detail overflow"))?;
            if detail.len() > MAX_ROWS {
                return Err(failed(
                    "bounded_input",
                    "native subledger has too many party/unit rows",
                ));
            }
        }
    }
    let mut rows = Vec::with_capacity(detail.len());
    let mut detail_totals = BTreeMap::new();
    for ((party_value, unit), columns) in detail {
        let (party, code) = &parties[&party_value];
        add_columns(detail_totals.entry(unit).or_insert([0; 4]), columns)?;
        rows.push(VerifiedNativeSubledgerRow {
            party: *party,
            party_value,
            party_code: code.clone(),
            unit,
            debits: columns[0],
            credits: columns[1],
            debits_pending: columns[2],
            credits_pending: columns[3],
        });
    }
    rows.sort_by(|a, b| a.party_code.cmp(&b.party_code).then(a.unit.cmp(&b.unit)));
    let control: BTreeMap<_, _> = control_rows
        .iter()
        .filter(|row| row.account == declaration.control)
        .map(|row| {
            (
                row.unit,
                [
                    row.debits,
                    row.credits,
                    row.debits_pending,
                    row.credits_pending,
                ],
            )
        })
        .collect();
    let selected_units: BTreeSet<_> = detail_totals
        .keys()
        .chain(control.keys())
        .copied()
        .collect();
    let mut reconciled = true;
    let totals = selected_units
        .into_iter()
        .map(|unit| {
            let detail = detail_totals.get(&unit).copied().unwrap_or([0; 4]);
            let control = control.get(&unit).copied().unwrap_or([0; 4]);
            reconciled &= detail == control;
            VerifiedNativeSubledgerTotal {
                unit,
                detail_debits: detail[0],
                detail_credits: detail[1],
                detail_debits_pending: detail[2],
                detail_credits_pending: detail[3],
                control_debits: control[0],
                control_credits: control[1],
                control_debits_pending: control[2],
                control_credits_pending: control[3],
            }
        })
        .collect();
    let report = VerifiedNativeSubledger {
        book_id: source.book,
        known_at: source.known_at,
        effective_through: certificate.request.effective_through,
        source_certificate_digest: source.digest,
        subledger_vid: identity(
            b"fa:vid:native-subledger:v1",
            &[&source.book, &declaration.control.to_le_bytes()],
        ),
        code: declaration.code,
        name: declaration.name,
        kind: declaration.kind,
        control_account: declaration.control,
        declaration_entry_vid: declaration.entry,
        declaration_entry_digest: declaration.digest,
        declared_at: declaration.recorded_at,
        rows,
        totals,
        reconciled,
    };
    let output = output(&report)?;
    if output != certificate.output {
        return Err(failed(
            "native_subledger_recomputation",
            "subledger designation, party identities, complete gross detail, control totals or canonical output differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn output(report: &VerifiedNativeSubledger) -> Result<Vec<u8>, ReportError> {
    let mut spec = Writer::default();
    spec.fixed(DESIGNATION_FORMAT)
        .bytes(report.code.as_bytes())
        .bytes(report.name.as_bytes())
        .u8(report.kind)
        .u128(report.control_account);
    let mut size = OUTPUT_FORMAT.len() + 16 + 4 + spec.buf.len() + 16 + 32 + 8 + 8 + 4 + 4 + 4 + 1;
    for row in &report.rows {
        size = size
            .checked_add(104 + row.party_code.len())
            .ok_or_else(|| failed("bounded_input", "native subledger output length overflow"))?;
    }
    size = size
        .checked_add(
            report
                .totals
                .len()
                .checked_mul(132)
                .ok_or_else(|| failed("bounded_input", "native subledger total length overflow"))?,
        )
        .ok_or_else(|| failed("bounded_input", "native subledger output length overflow"))?;
    if size > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "native subledger output exceeds 64 MiB",
        ));
    }
    let mut w = Writer::default();
    w.fixed(OUTPUT_FORMAT)
        .u128(report.subledger_vid)
        .bytes(&spec.buf)
        .u128(report.declaration_entry_vid)
        .fixed(&report.declaration_entry_digest)
        .u64(report.declared_at)
        .u64(report.known_at)
        .i32(report.effective_through)
        .count(report.rows.len());
    for row in &report.rows {
        w.u128(row.party)
            .u128(row.party_value)
            .bytes(row.party_code.as_bytes())
            .u32(row.unit)
            .i128(row.debits)
            .i128(row.credits)
            .i128(row.debits_pending)
            .i128(row.credits_pending);
    }
    w.count(report.totals.len());
    for row in &report.totals {
        w.u32(row.unit)
            .i128(row.detail_debits)
            .i128(row.detail_credits)
            .i128(row.detail_debits_pending)
            .i128(row.detail_credits_pending)
            .i128(row.control_debits)
            .i128(row.control_credits)
            .i128(row.control_debits_pending)
            .i128(row.control_credits_pending);
    }
    w.u8(u8::from(report.reconciled));
    Ok(w.buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(w: &mut Writer, digest: u8) {
        w.fixed(&[digest; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
    }

    fn party(identifiers: &[(&str, u8)], external: &[(&str, u8)]) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(b"customer-a").u8(1);
        field(&mut w, 0);
        w.count(identifiers.len());
        for (key, digest) in identifiers {
            w.bytes(key.as_bytes());
            field(&mut w, *digest);
        }
        w.count(external.len());
        for (system, digest) in external {
            w.bytes(system.as_bytes());
            field(&mut w, *digest);
        }
        w.buf
    }

    #[test]
    fn party_identity_requires_the_entire_canonical_declaration() {
        let original = party(&[("tax", 1)], &[("erp", 1), ("erp", 2)]);
        assert_eq!(party_code(&original).unwrap(), "customer-a");
        for end in 0..original.len() {
            assert!(party_code(&original[..end]).is_err());
        }
        let mut trailing = original;
        trailing.push(0);
        assert!(party_code(&trailing).is_err());
        for invalid in [
            party(&[("", 1)], &[]),
            party(&[("tax", 1), ("tax", 2)], &[]),
            party(&[("z", 1), ("a", 2)], &[]),
            party(&[], &[("", 1)]),
            party(&[], &[("erp", 2), ("erp", 1)]),
            party(&[], &[("erp", 1), ("erp", 1)]),
            party(&vec![("tax", 1); 33], &[]),
        ] {
            assert!(party_code(&invalid).is_err());
        }
    }

    #[test]
    fn outer_digest_and_recipient_question_are_separate_checks() {
        let expected = NativeSubledgerRequest {
            code: "AR".into(),
            control_account: 42,
            effective_through: 365,
            known_at: 12,
        };
        let mut w = Writer::default();
        w.bytes(CERTIFICATE_FORMAT)
            .bytes(b"nested source")
            .bytes(expected.code.as_bytes())
            .u128(expected.control_account)
            .i32(expected.effective_through)
            .u64(expected.known_at)
            .fixed(&[1; 32])
            .u128(7)
            .fixed(&[2; 32])
            .bytes(OUTPUT_FORMAT);
        let digest = hash_parts(
            CERTIFICATE_DIGEST,
            &[&(w.buf.len() as u32).to_le_bytes(), &w.buf],
        );
        w.fixed(&digest);
        let certificate = decode(&w.buf).unwrap();
        bind_request(&certificate, &expected).unwrap();
        for wrong in [
            NativeSubledgerRequest {
                code: "AP".into(),
                ..expected.clone()
            },
            NativeSubledgerRequest {
                control_account: 43,
                ..expected.clone()
            },
            NativeSubledgerRequest {
                effective_through: 366,
                ..expected.clone()
            },
            NativeSubledgerRequest {
                known_at: 13,
                ..expected.clone()
            },
        ] {
            assert_eq!(
                bind_request(&certificate, &wrong).unwrap_err().predicate,
                "native_subledger_request"
            );
        }
        for end in 0..w.buf.len() {
            assert!(decode(&w.buf[..end]).is_err());
        }
        let last = w.buf.len() - 1;
        w.buf[last] ^= 1;
        assert_eq!(
            decode(&w.buf).err().unwrap().predicate,
            "certificate_digest"
        );
    }
}
