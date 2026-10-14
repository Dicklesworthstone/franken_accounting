//! Canonical split inputs and bounded output primitives; no source authority.

use fa_model::{DecodeError, Reader, domain_digest};
use super::*;

pub(super) struct Wire { bytes: Vec<u8>, limit: usize }
impl Wire {
    pub(super) fn new(limit: usize) -> Self { Self { bytes: Vec::new(), limit } }
    pub(super) fn fixed(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.bytes.len().checked_add(bytes.len()).is_none_or(|n| n > self.limit) {
            return Err(invalid("cash split encoding exceeds its total byte bound"));
        }
        self.bytes.try_reserve(bytes.len()).map_err(|_| invalid("cannot reserve cash split encoding"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(super) fn count(&mut self, count: usize) -> Result<(), Refusal> {
        let count = u32::try_from(count).map_err(|_| invalid("cash split count exceeds its wire bound"))?;
        self.fixed(&count.to_le_bytes())
    }
    pub(super) fn bytes(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.count(bytes.len())?;
        self.fixed(bytes)
    }
    pub(super) fn text(&mut self, text: &str) -> Result<(), Refusal> { self.bytes(text.as_bytes()) }
    pub(super) fn finish(self) -> Vec<u8> { self.bytes }
}

/// Bound all input counts, strings and expanded encoded size BEFORE cloning.
/// Positive portions and unique activities make the partition representation
/// unambiguous. Canonicalization never merges duplicate user decisions.
pub(super) fn normalize(value: &CashFlowSplitDefinition) -> Result<CashFlowSplitDefinition, Refusal> {
    if value.name.trim().is_empty() || value.name.len() > 256
        || value.cash_accounts.is_empty() || value.cash_accounts.len() > MAX_CASH_FLOW_SPLIT_ACCOUNTS
        || value.splits.len() > MAX_GENERAL_LEDGER_LINES
    { return Err(invalid("cash split definition has an invalid name or excessive scope")); }
    let mut size = 4 + CASH_FLOW_SPLIT_DEFINITION_FORMAT.len() + 4 + value.name.len()
        + 4 + value.cash_accounts.len() * 16 + 4;
    for split in &value.splits {
        if split.reason.trim().is_empty() || split.reason.len() > 256
            || split.portions.is_empty() || split.portions.len() > MAX_CASH_FLOW_SPLIT_PARTS_PER_LEG
        { return Err(invalid("each cash split requires a bounded reason and one to five portions")); }
        let mut activities = [false; 5];
        for portion in &split.portions {
            if portion.amount <= 0 || activities[portion.activity as usize] {
                return Err(invalid("cash split portions must be positive with distinct activity classes"));
            }
            activities[portion.activity as usize] = true;
        }
        let additional = 32 + 4 + 4 + split.reason.len() + 4 + split.portions.len() * 17;
        size = size.checked_add(additional)
            .filter(|n| *n <= MAX_CASH_FLOW_SPLIT_DEFINITION_BYTES)
            .ok_or_else(|| invalid("cash split definition exceeds its expanded 32 MiB bound"))?;
    }
    let mut out = value.clone();
    out.cash_accounts.sort_unstable();
    out.splits.sort_unstable_by_key(|s| (s.entry_digest, s.leg_index));
    if out.cash_accounts.windows(2).any(|p| p[0] == p[1])
        || out.splits.windows(2).any(|p| (p[0].entry_digest, p[0].leg_index) == (p[1].entry_digest, p[1].leg_index))
    { return Err(invalid("cash split definition repeats an account or original leg")); }
    for split in &mut out.splits { split.portions.sort_unstable_by_key(|p| p.activity as u8); }
    Ok(out)
}

fn encode(value: &CashFlowSplitDefinition) -> Result<Vec<u8>, Refusal> {
    let mut w = Wire::new(MAX_CASH_FLOW_SPLIT_DEFINITION_BYTES);
    w.text(CASH_FLOW_SPLIT_DEFINITION_FORMAT)?;
    w.text(&value.name)?;
    w.count(value.cash_accounts.len())?;
    for account in &value.cash_accounts { w.fixed(&account.to_le_bytes())?; }
    w.count(value.splits.len())?;
    for split in &value.splits {
        w.fixed(&split.entry_digest)?;
        w.fixed(&split.leg_index.to_le_bytes())?;
        w.text(&split.reason)?;
        w.count(split.portions.len())?;
        for portion in &split.portions {
            w.fixed(&[portion.activity as u8])?;
            w.fixed(&portion.amount.to_le_bytes())?;
        }
    }
    Ok(w.finish())
}

impl CashFlowSplitDefinition {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> { encode(&normalize(self)?) }

    /// Independent custody of this digest fixes ALL split decisions and reasons,
    /// not only the net cash result. It is not an approval or native proof.
    pub fn digest(&self) -> Result<[u8; 32], Refusal> {
        Ok(domain_digest(b"fa:cash-flow-split-definition-digest:v1", &[&self.canonical_bytes()?]))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CASH_FLOW_SPLIT_DEFINITION_BYTES {
            return Err(invalid("cash split definition exceeds its 32 MiB byte bound"));
        }
        let malformed = |e: DecodeError| invalid(format!("malformed cash split definition: {e}"));
        let mut r = Reader::new(bytes);
        if r.str(64, "cash split definition format").map_err(malformed)? != CASH_FLOW_SPLIT_DEFINITION_FORMAT {
            return Err(invalid("unsupported cash split definition format"));
        }
        let name = r.str(256, "cash split name").map_err(malformed)?.to_string();
        let count = r.count(MAX_CASH_FLOW_SPLIT_ACCOUNTS, "cash split accounts").map_err(malformed)?;
        if count == 0 || count > r.remaining() / 16 { return Err(invalid("empty or truncated cash split account scope")); }
        let mut cash_accounts = Vec::with_capacity(count);
        for _ in 0..count { cash_accounts.push(r.u128("cash split account").map_err(malformed)?); }
        let count = r.count(MAX_GENERAL_LEDGER_LINES, "cash splits").map_err(malformed)?;
        // Even an empty reason with one portion requires 61 bytes per split.
        if count > r.remaining() / 61 { return Err(invalid("truncated cash split list")); }
        let mut splits = Vec::with_capacity(count);
        for _ in 0..count {
            let entry_digest = r.fixed("cash split entry").map_err(malformed)?;
            let leg_index = r.u32("cash split ordinal").map_err(malformed)?;
            let reason = r.str(256, "cash split reason").map_err(malformed)?.to_string();
            let count = r.count(MAX_CASH_FLOW_SPLIT_PARTS_PER_LEG, "cash split portions").map_err(malformed)?;
            if count == 0 || count > r.remaining() / 17 { return Err(invalid("empty or truncated cash split portions")); }
            let mut portions = Vec::with_capacity(count);
            for _ in 0..count {
                let activity = match r.u8("cash split activity").map_err(malformed)? {
                    0 => CashFlowActivity::Operating, 1 => CashFlowActivity::Investing,
                    2 => CashFlowActivity::Financing, 3 => CashFlowActivity::ExchangeEffect,
                    4 => CashFlowActivity::InternalTransfer,
                    _ => return Err(invalid("unknown cash split activity")),
                };
                portions.push(CashFlowPortion { activity, amount: r.i128("cash split amount").map_err(malformed)? });
            }
            splits.push(CashFlowLegSplit { entry_digest, leg_index, reason, portions });
        }
        r.finish().map_err(malformed)?;
        let value = Self { name, cash_accounts, splits };
        if normalize(&value)? != value || encode(&value)?.as_slice() != bytes {
            return Err(invalid("cash split definition is not canonically ordered"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> CashFlowSplitDefinition {
        CashFlowSplitDefinition { name: "Loan €".into(), cash_accounts: vec![9],
            splits: vec![CashFlowLegSplit { entry_digest: [7; 32], leg_index: 2, reason: "Interest and principal".into(),
                portions: vec![CashFlowPortion { activity: CashFlowActivity::Operating, amount: 3 },
                    CashFlowPortion { activity: CashFlowActivity::Financing, amount: 97 }] }] }
    }
    #[test]
    fn split_definition_roundtrips_and_preserves_independent_wire_layout() {
        let value = example();
        let mut expected = Vec::new();
        let field = |out: &mut Vec<u8>, b: &[u8]| { out.extend_from_slice(&(b.len() as u32).to_le_bytes()); out.extend_from_slice(b); };
        field(&mut expected, CASH_FLOW_SPLIT_DEFINITION_FORMAT.as_bytes());
        field(&mut expected, "Loan €".as_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes()); expected.extend_from_slice(&9u128.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes()); expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&2u32.to_le_bytes()); field(&mut expected, b"Interest and principal");
        expected.extend_from_slice(&2u32.to_le_bytes());
        for (tag, amount) in [(0, 3i128), (2, 97)] { expected.push(tag); expected.extend_from_slice(&amount.to_le_bytes()); }
        assert_eq!(value.canonical_bytes().unwrap(), expected);
        assert_eq!(CashFlowSplitDefinition::decode(&expected).unwrap(), value);
    }
    #[test]
    fn duplicate_nonpositive_and_empty_decisions_are_not_normalized_away() {
        let value = example();
        for amount in [0, -1, i128::MIN] {
            let mut bad = value.clone(); bad.splits[0].portions[0].amount = amount;
            assert!(bad.canonical_bytes().is_err());
        }
        let mut bad = value.clone(); let repeated = bad.splits[0].portions[0]; bad.splits[0].portions.push(repeated);
        assert!(bad.canonical_bytes().is_err());
        let mut bad = value.clone(); bad.splits.push(bad.splits[0].clone());
        assert!(bad.canonical_bytes().is_err());
        let mut bad = value.clone(); bad.cash_accounts.push(9);
        assert!(bad.canonical_bytes().is_err());
        let mut bad = value.clone(); bad.splits[0].reason = " ".into();
        assert!(bad.canonical_bytes().is_err());
        let mut bad = value; bad.splits[0].portions.clear();
        assert!(bad.canonical_bytes().is_err());
    }
    #[test]
    fn every_truncation_bad_tag_noncanonical_order_and_trailing_byte_refuses() {
        let value = example(); let bytes = value.canonical_bytes().unwrap();
        for end in 0..bytes.len() { assert!(CashFlowSplitDefinition::decode(&bytes[..end]).is_err(), "prefix {end}"); }
        let mut bad = bytes.clone(); bad.push(0); assert!(CashFlowSplitDefinition::decode(&bad).is_err());
        let mut bad = bytes.clone(); let n = bad.len(); bad[n - 17] = 255;
        assert!(CashFlowSplitDefinition::decode(&bad).is_err());
        let mut reversed = value; reversed.splits[0].portions.reverse();
        assert!(CashFlowSplitDefinition::decode(&encode(&reversed).unwrap()).is_err());
        assert_eq!(reversed.canonical_bytes().unwrap(), bytes);
    }
    #[test]
    fn changing_reason_or_split_without_changing_total_changes_identity() {
        let value = example(); let digest = value.digest().unwrap();
        let mut other = value.clone(); other.splits[0].reason.push('!'); assert_ne!(other.digest().unwrap(), digest);
        let mut other = value; other.splits[0].portions[0].amount += 1; other.splits[0].portions[1].amount -= 1;
        assert_ne!(other.digest().unwrap(), digest);
    }
    #[test]
    fn bounded_writer_checks_before_copying_or_overflowing() {
        let mut w = Wire::new(3); w.fixed(b"abc").unwrap(); assert!(w.fixed(b"d").is_err()); assert_eq!(w.finish(), b"abc");
        let mut w = Wire::new(0); assert!(w.fixed(b"a").is_err()); assert!(w.finish().is_empty());
    }
}
