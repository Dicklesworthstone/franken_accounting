//! Bounded, canonical transport; decoding is not native-history verification.

use fa_model::{DecodeError, Id128, Reader};

use super::*;
use super::super::{AdjustmentCategory, AdjustmentSign, Bytes, INDIRECT_CASH_FLOW_FORMAT,
    IndirectCashFlowAdjustment, MAX_PERIODS, bounded, write_definition};
use crate::general_ledger::MAX_GENERAL_LEDGER_LINES;

fn read_periods(r: &mut Reader<'_>) -> Result<Vec<String>, DecodeError> {
    let count = r.count(MAX_PERIODS, "indirect income periods")?;
    if count == 0 || count > r.remaining() / 4 {
        return Err(r.invalid("empty or truncated indirect income periods"));
    }
    let mut selected = Vec::with_capacity(count);
    for _ in 0..count { selected.push(r.str(128, "indirect income period")?.to_string()); }
    if periods(&selected).map_err(|_| r.invalid("invalid indirect income periods"))? != selected {
        return Err(r.invalid("indirect income periods must be strictly ordered"));
    }
    Ok(selected)
}

fn read_definition(r: &mut Reader<'_>) -> Result<IndirectCashFlowDefinition, DecodeError> {
    let name = r.str(256, "indirect definition name")?.to_string();
    let count = r.count(MAX_GENERAL_LEDGER_LINES, "indirect adjustments")?;
    // Every row has 32 digest + 4 ordinal + 2 tags + 4 reason-length bytes,
    // BEFORE its required nonempty reason. Do not allocate from a bare count.
    if count > r.remaining() / 42 { return Err(r.invalid("truncated indirect adjustment population")); }
    let mut adjustments = Vec::with_capacity(count);
    for _ in 0..count {
        let entry_digest = r.fixed("indirect entry digest")?;
        let leg_index = r.u32("indirect leg index")?;
        let category = match r.u8("indirect category")? {
            0 => AdjustmentCategory::NonCash,
            1 => AdjustmentCategory::WorkingCapital,
            2 => AdjustmentCategory::NonOperating,
            _ => return Err(r.invalid("unknown indirect adjustment category")),
        };
        let sign = match r.u8("indirect sign")? {
            0 => AdjustmentSign::DebitMinusCredit,
            1 => AdjustmentSign::CreditMinusDebit,
            _ => return Err(r.invalid("unknown indirect adjustment sign")),
        };
        let reason = r.str(256, "indirect reason")?.to_string();
        adjustments.push(IndirectCashFlowAdjustment { entry_digest, leg_index, category, sign, reason });
    }
    let value = IndirectCashFlowDefinition { name, adjustments };
    if normalize(&value).map_err(|_| r.invalid("invalid indirect definition"))? != value {
        return Err(r.invalid("indirect adjustments must be strictly ordered"));
    }
    Ok(value)
}

fn size(source: usize, selected: &[String], definition: &IndirectCashFlowDefinition,
    output: usize) -> Result<usize, Refusal>
{
    let mut total = 0usize;
    for n in [4, INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT.len(), 4, source, 4,
        4, definition.name.len(), 4, 4, output, 32]
    { total = bounded(total, n).map_err(as_invalid)?; }
    for period in selected {
        total = bounded(total, 4).and_then(|n| bounded(n, period.len())).map_err(as_invalid)?;
    }
    for adjustment in &definition.adjustments {
        total = bounded(total, 42).and_then(|n| bounded(n, adjustment.reason.len())).map_err(as_invalid)?;
    }
    Ok(total)
}

/// Bind the existing output headers without inventing another report decoder.
/// Amounts, periods, definitions and all remaining source bytes stay opaque
/// here: only full native replay and the exact byte comparison validate them.
fn check_output(output: &[u8], source: &CashFlowCertificate) -> Result<(), DecodeError> {
    let mut r = Reader::new(output);
    if r.str(64, "indirect output format")? != INDIRECT_CASH_FLOW_FORMAT
        || r.bytes(MAX_INDIRECT_CASH_FLOW_BYTES, "indirect direct cash output")? != source.output()
    { return Err(r.invalid("indirect output does not bind its original direct cash report")); }
    let mut income = Reader::new(r.bytes(MAX_INDIRECT_CASH_FLOW_BYTES, "indirect income output")?);
    if income.fixed::<13>("income magic")? != *b"FA-STATEMENT\0"
        || income.u16("income major")? != 1 || income.u16("income minor")? != 0
        || income.fixed::<16>("income book")? != source.source_certificate().source_certificate().book_id.0
        || income.fixed::<16>("income branch")? != Id128::TRUNK.0
        || income.u64("income known-at")? != source.known_at().0
    { return Err(income.invalid("indirect income header differs from its native source")); }
    Ok(())
}

impl IndirectCashFlowCertificate {
    pub(super) fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.output.len() > MAX_INDIRECT_CASH_FLOW_BYTES
            || periods(&self.income_periods).map_err(as_invalid)? != self.income_periods
            || normalize(&self.definition).map_err(as_invalid)? != self.definition
        { return Err(invalid("noncanonical indirect certificate parameters or excessive output")); }
        check_output(&self.output, &self.source).map_err(|e| invalid(e.to_string()))?;
        let source = self.source.canonical_bytes()?;
        let expected_size = size(source.len(), &self.income_periods, &self.definition, self.output.len())?;
        let build = || -> Result<Vec<u8>, Refusal> {
            let mut out = Bytes::default();
            out.blob(INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT)?;
            out.blob(&source)?;
            out.count(self.income_periods.len())?;
            for period in &self.income_periods { out.string(period)?; }
            write_definition(&mut out, &self.definition)?;
            out.blob(&self.output)?;
            if out.0.len().checked_add(32) != Some(expected_size) {
                return Err(invalid("indirect certificate size accounting disagrees with its encoding"));
            }
            Ok(out.0)
        };
        build().map_err(as_invalid)
    }

    /// Canonical, bounded confidential transport. No signature or authority is
    /// conferred by its content digest. Retain the expected inputs separately.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&body]) != self.digest {
            return Err(invalid("indirect certificate digest differs from its contents"));
        }
        bounded(body.len(), 32).map_err(as_invalid)?;
        body.try_reserve(32).map_err(|_| invalid("cannot reserve indirect certificate digest"))?;
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    /// Validate bounded framing, canonical parameters, nested source integrity
    /// and the unkeyed digest. Never construct a trusted report from these bytes;
    /// use AsyncBook::replay_indirect_cash_flow under current authority instead.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_INDIRECT_CASH_FLOW_CERTIFICATE_BYTES {
            return Err(invalid("indirect certificate exceeds its 64 MiB total bound"));
        }
        let malformed = |e: DecodeError| invalid(format!("malformed indirect certificate: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "indirect certificate format").map_err(malformed)? != INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT {
            return Err(invalid("unsupported indirect certificate format"));
        }
        let source = CashFlowCertificate::decode(r.bytes(MAX_INDIRECT_CASH_FLOW_CERTIFICATE_BYTES,
            "indirect native source").map_err(malformed)?)?;
        let income_periods = read_periods(&mut r).map_err(malformed)?;
        let definition = read_definition(&mut r).map_err(malformed)?;
        let output = r.bytes(MAX_INDIRECT_CASH_FLOW_BYTES, "indirect report output")
            .map_err(malformed)?.to_vec();
        let digest = r.fixed("indirect certificate digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self { source, income_periods, definition, output, digest };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical indirect certificate bytes"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn definition() -> IndirectCashFlowDefinition {
        IndirectCashFlowDefinition { name: "Policy".into(), adjustments: vec![IndirectCashFlowAdjustment {
            entry_digest: [7; 32], leg_index: 19, category: AdjustmentCategory::WorkingCapital,
            sign: AdjustmentSign::CreditMinusDebit, reason: "AR €".into(),
        }] }
    }
    fn encoded(definition: &IndirectCashFlowDefinition) -> Vec<u8> {
        let mut out = Bytes::default();
        write_definition(&mut out, definition).unwrap();
        out.0
    }
    #[test]
    fn definition_layout_is_independently_pinned_and_covers_all_category_sign_pairs() {
        let mut d = definition();
        let mut expected = vec![6, 0, 0, 0]; // UTF-8 byte lengths, little endian
        expected.extend_from_slice(b"Policy");
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&19u32.to_le_bytes());
        expected.extend_from_slice(&[1, 1]);
        expected.extend_from_slice(&6u32.to_le_bytes());
        expected.extend_from_slice("AR €".as_bytes());
        assert_eq!(encoded(&d), expected);
        for category in [AdjustmentCategory::NonCash, AdjustmentCategory::WorkingCapital, AdjustmentCategory::NonOperating] {
            for sign in [AdjustmentSign::DebitMinusCredit, AdjustmentSign::CreditMinusDebit] {
                d.adjustments[0].category = category;
                d.adjustments[0].sign = sign;
                let bytes = encoded(&d);
                let mut r = Reader::new(&bytes);
                assert_eq!(read_definition(&mut r).unwrap(), d);
                r.finish().unwrap();
            }
        }
    }
    #[test]
    fn hostile_counts_unknown_tags_utf8_duplicates_and_every_definition_truncation_refuse() {
        let good = encoded(&definition());
        for cut in 0..good.len() { assert!(read_definition(&mut Reader::new(&good[..cut])).is_err()); }
        let mut bad = good.clone();
        bad[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_definition(&mut Reader::new(&bad)).is_err());
        for index in [50, 51] { // category and sign after the 36-byte citation
            let mut bad = good.clone(); bad[index] = 255;
            assert!(read_definition(&mut Reader::new(&bad)).is_err());
        }
        let mut bad = good; bad[4] = 255;
        assert!(read_definition(&mut Reader::new(&bad)).is_err());
        let mut repeated = definition(); repeated.adjustments.push(repeated.adjustments[0].clone());
        assert!(read_definition(&mut Reader::new(&encoded(&repeated))).is_err());
        let mut empty_reason = definition(); empty_reason.adjustments[0].reason = " ".into();
        assert!(read_definition(&mut Reader::new(&encoded(&empty_reason))).is_err());
    }
    #[test]
    fn periods_require_canonical_order_and_size_prediction_includes_every_length_prefix() {
        for values in [vec![], vec!["P2", "P1"], vec!["P1", "P1"], vec![""]] {
            let mut out = Bytes::default(); out.count(values.len()).unwrap();
            for p in values { out.string(p).unwrap(); }
            assert!(read_periods(&mut Reader::new(&out.0)).is_err());
        }
        let d = definition();
        let p = vec!["P1".into()];
        let source = [3; 9]; let output = [5; 17];
        let mut out = Bytes::default();
        out.blob(INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT).unwrap();
        out.blob(&source).unwrap(); out.count(1).unwrap(); out.string("P1").unwrap();
        write_definition(&mut out, &d).unwrap(); out.blob(&output).unwrap(); out.add(&[0; 32]).unwrap();
        assert_eq!(size(source.len(), &p, &d, output.len()).unwrap(), out.0.len());
        assert!(size(usize::MAX, &p, &d, 0).is_err());
        assert!(size(MAX_INDIRECT_CASH_FLOW_CERTIFICATE_BYTES, &p, &d, 0).is_err());
    }
}
