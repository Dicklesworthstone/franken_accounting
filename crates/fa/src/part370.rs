//! FDIC 12 CFR Part 370 from the book (plan §15.6 workflow 3, bead
//! `fa-p370`): the deposit accounts, their participants and customers, and
//! the open holds at an end-of-day effective date and one known-at prefix,
//! as the `fa_formats::part370` profile reads them.
//!
//! - Accounts are the book's `Deposit` instruments. Each takes the deposit
//!   profile valid on the day (its capacity, product, primary customer,
//!   participants); a deposit without one is refused.
//! - A deposit's current balance is its mirrored Liability leaf's posted
//!   stock on the day (credits less debits); its accrued interest is its
//!   profile's interest leaf's, or zero when the profile names none; its
//!   hold amount is the leaf's pending debits.
//! - Pending items are the open `Pending` entries' debit legs on deposit
//!   leaves (a hold effective on or before the day whose resolution, if
//!   any, is effective after it), one item per hold and deposit, named by
//!   the hold's idempotency key and described by its description. They
//!   must fold to the hold amounts.
//! - Customers are the participating parties. Their Part 370 fields are
//!   party identifiers under the keys in [`PART370_IDENTIFIER_KEYS`];
//!   `tax_id` and `tax_id_type` are required. A party with `given_name` or
//!   `family_name` is an individual; any other is an entity named by its
//!   party name.
//!
//! The deposit insurance figures are the profile's deterministic owner and
//! capacity aggregation; whether they are sufficient for the rule is the
//! regulator's or counsel's determination.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_formats::part370::{
    FDIC_SDIA_USD_CENTS, Part370AccountParticipantEdge, Part370BankBook, Part370Customer,
    Part370DepositAccount, Part370ParticipantRole, Part370PendingItem,
};
use fa_journal::{KernelError, PartyRow, Refusal, exit, refusal::code};
use fa_model::rea::MAX_IDENTIFIER_VAL_BYTES;
use fa_model::{DepositRole, EntryClass, InstrumentKind, SealKey, limits};
use fa_money::Side;
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome};

/// The party identifier keys a Part 370 customer record reads.
pub const PART370_IDENTIFIER_KEYS: [&str; 11] = [
    "given_name",
    "middle_name",
    "family_name",
    "name_suffix",
    "tax_id",
    "tax_id_type",
    "street_address_1",
    "city",
    "state",
    "postal_code",
    "country",
];

fn incomplete(message: String, fix: &str) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §15.6 workflow 3 (FDIC Part 370 deposit, participant and customer records)",
        fix.to_string(),
    )
}

fn role(role: DepositRole) -> Part370ParticipantRole {
    match role {
        DepositRole::Owner => Part370ParticipantRole::Own,
        DepositRole::Beneficiary => Part370ParticipantRole::Ben,
        DepositRole::Agent => Part370ParticipantRole::Agt,
        DepositRole::Trustee => Part370ParticipantRole::Tst,
    }
}

/// One customer record from its party. A value the book's key does not open
/// (erased) reads as absent.
fn customer(key: &SealKey, party: &PartyRow) -> Result<Part370Customer, Refusal> {
    let field = |name: &str| -> String {
        party
            .identifiers
            .iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| v.open(key, MAX_IDENTIFIER_VAL_BYTES).ok())
            .unwrap_or_default()
    };
    let required = |name: &str| -> Result<String, Refusal> {
        let value = field(name);
        if value.is_empty() {
            return Err(incomplete(
                format!(
                    "customer `{}` has no `{name}` identifier; Part 370's customer file requires it",
                    party.code
                ),
                "record it with fa party identifiers <code> --identifier tax_id=... --identifier tax_id_type=... (the set replaces the party's identifiers: name every one it keeps)",
            ));
        }
        Ok(value)
    };
    let given = field("given_name");
    let family = field("family_name");
    let individual = !given.is_empty() || !family.is_empty();
    let entity_name = if individual {
        String::new()
    } else {
        let name = party
            .name
            .open(key, fa_model::rea::MAX_REA_NAME_BYTES)
            .unwrap_or_default();
        if name.is_empty() {
            return Err(incomplete(
                format!(
                    "customer `{}` has neither a readable name nor given_name/family_name identifiers",
                    party.code
                ),
                "record the individual's name parts as identifiers, or the entity's name on the party",
            ));
        }
        name
    };
    Ok(Part370Customer {
        cs_unique_id: party.code.clone(),
        first_name: given,
        middle_name: field("middle_name"),
        last_name: family,
        name_suffix: field("name_suffix"),
        entity_name,
        tax_id: required("tax_id")?,
        tax_id_type: required("tax_id_type")?,
        street_address_1: field("street_address_1"),
        city: field("city"),
        state: field("state"),
        postal_code: field("postal_code"),
        country: field("country"),
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// The Part 370 input snapshot at end of day `as_of`, as known at
    /// `known_at` (HEAD when `None`), under whole-book read authority. Its
    /// coordinate is the book's interop export coordinate at the same
    /// effective date and prefix, so the files bind the journal they read.
    pub fn part370_book(
        &self,
        cx: &PurposeContexts,
        as_of: DateDay,
        known_at: Option<CommitSeq>,
        capability: &fa_policy::Capability,
    ) -> Outcome<Part370BankBook> {
        let built = self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let rea = fa_journal::read_rea_at(db, book, at)?;
            let tb = fa_registers::balance_as_of(db, book, as_of, Some(at))?;
            let rows: BTreeMap<(VId, u32), &fa_registers::TbRow> = tb
                .rows
                .iter()
                .map(|row| ((row.account, row.unit_id), row))
                .collect();
            let posted = |account: VId, unit: u32| -> Result<(i128, i128), BookError> {
                rows.get(&(account, unit)).map_or(Ok((0, 0)), |row| {
                    let stock = row
                        .credits
                        .checked_sub(row.debits)
                        .ok_or(fa_registers::RegisterError::Overflow)?;
                    Ok((stock, row.debits_pending))
                })
            };
            let mut deposits: Vec<_> = rea
                .instruments
                .values()
                .filter(|i| i.kind == InstrumentKind::Deposit)
                .collect();
            deposits.sort_by(|a, b| a.code.cmp(&b.code));
            // One leaf answers for one deposit: a shared leaf would count
            // one balance twice.
            let mut leaves: BTreeMap<VId, &str> = BTreeMap::new();
            let mut by_leaf: BTreeMap<VId, (&str, fa_money::UnitId, &'static str)> =
                BTreeMap::new();
            let mut accounts = Vec::new();
            let mut participants = Vec::new();
            let mut parties: BTreeSet<VId> = BTreeSet::new();
            for deposit in &deposits {
                let unit = book.units.get(deposit.unit).ok_or_else(|| {
                    KernelError::Corrupt(format!("deposit `{}` has no registered unit", deposit.code))
                })?;
                if unit.code != "USD" || unit.scale != 2 {
                    return Ok(Err(incomplete(
                        format!(
                            "deposit `{}` is in {}; this Part 370 profile reads USD deposits at scale 2",
                            deposit.code, unit.code
                        ),
                        "export Part 370 for a book whose deposits are USD instruments",
                    )));
                }
                let Some(profile) = rea.deposit_profile_on(deposit.vid, as_of) else {
                    return Ok(Err(incomplete(
                        format!(
                            "deposit `{}` has no participant profile valid on {as_of}: its ownership capacity is unknown",
                            deposit.code
                        ),
                        "record one with fa instrument profile <profile.json> (capacity, product, primary, participants, valid_from on or before the day)",
                    )));
                };
                let spec = &profile.spec;
                for (leaf, what) in [(Some(deposit.mirrors_account), "deposit"), (spec.interest_account, "interest")] {
                    let Some(leaf) = leaf else { continue };
                    if let Some(other) = leaves.insert(leaf, &deposit.code) {
                        return Ok(Err(incomplete(
                            format!(
                                "deposits `{other}` and `{}` share one leaf ({what}); Part 370 reads one balance per deposit account",
                                deposit.code
                            ),
                            "give every deposit, and its interest, a leaf of its own",
                        )));
                    }
                }
                let (balance, hold) = posted(deposit.mirrors_account, deposit.unit.0)?;
                let interest = match spec.interest_account {
                    Some(leaf) => posted(leaf, deposit.unit.0)?.0,
                    None => 0,
                };
                by_leaf.insert(
                    deposit.mirrors_account,
                    (deposit.code.as_str(), deposit.unit, spec.capacity.code()),
                );
                let code_of = |vid: VId| -> Result<String, BookError> {
                    rea.parties.get(&vid).map(|p| p.code.clone()).ok_or_else(|| {
                        KernelError::Corrupt(format!(
                            "deposit `{}` names absent party {:032x}",
                            deposit.code, vid.0
                        ))
                        .into()
                    })
                };
                accounts.push(Part370DepositAccount {
                    dp_acct_id: deposit.code.clone(),
                    primary_cs_unique_id: code_of(spec.primary_party)?,
                    dp_right_capacity: Some(spec.capacity.code().to_string()),
                    prod_cat: spec.product.code().to_string(),
                    unit_code: unit.code.clone(),
                    scale: unit.scale,
                    current_balance_mantissa: balance,
                    accrued_interest_mantissa: interest,
                    hold_amount_mantissa: hold,
                });
                for p in &spec.participants {
                    parties.insert(p.party);
                    participants.push(Part370AccountParticipantEdge {
                        dp_acct_id: deposit.code.clone(),
                        cs_unique_id: code_of(p.party)?,
                        ap_right_capacity: Some(spec.capacity.code().to_string()),
                        participant_role: role(p.role),
                        ownership_pct_bps: p.ownership_bps,
                        beneficiary_count: p.beneficiary_count,
                    });
                }
            }
            let mut customers = Vec::new();
            for vid in &parties {
                let party = rea.parties.get(vid).ok_or_else(|| {
                    KernelError::Corrupt(format!("a deposit names absent party {:032x}", vid.0))
                })?;
                match customer(&book.seal_key, party) {
                    Ok(c) => customers.push(c),
                    Err(refusal) => return Ok(Err(refusal)),
                }
            }
            // Open holds on deposit leaves at the coordinate.
            let entries = fa_registers::entries_at(db, book, at)?;
            let resolved: BTreeSet<VId> = entries
                .iter()
                .filter(|(_, e, _)| {
                    e.proposal.class == EntryClass::RESOLUTION
                        && e.proposal.effective_date <= as_of
                })
                .filter_map(|(_, e, _)| e.proposal.pending.as_ref()?.resolution_of)
                .map(|target| target.vid)
                .collect();
            // One item per (hold, deposit): the hold's debit legs on the
            // deposit's leaf, identified by the hold's idempotency key and
            // described by its description.
            let mut items: BTreeMap<(VId, String), Part370PendingItem> = BTreeMap::new();
            let mut held: BTreeMap<VId, i128> = BTreeMap::new();
            for (vid, entry, _) in &entries {
                let proposal = &entry.proposal;
                if proposal.class != EntryClass::PENDING
                    || proposal.effective_date > as_of
                    || resolved.contains(vid)
                {
                    continue;
                }
                let mut on_leaf: BTreeMap<VId, i128> = BTreeMap::new();
                for leg in &proposal.legs {
                    let Some(&(_, unit, _)) = by_leaf.get(&leg.account_ref) else {
                        continue;
                    };
                    if leg.side != Side::Debit || leg.amount.unit != unit {
                        continue;
                    }
                    let sum = on_leaf.entry(leg.account_ref).or_insert(0);
                    *sum = sum
                        .checked_add(leg.amount.mantissa)
                        .ok_or(fa_registers::RegisterError::Overflow)?;
                }
                if on_leaf.is_empty() {
                    continue;
                }
                let Ok(pending_id) = String::from_utf8(proposal.idempotency_key.clone()) else {
                    return Ok(Err(incomplete(
                        format!(
                            "hold {:032x} on a deposit has an idempotency key that is not text; Part 370 names a pending item by it",
                            vid.0
                        ),
                        "place holds on deposits with a text idempotency key (fa reserve --intent with \"idempotency_key\")",
                    )));
                };
                for (leaf, amount) in on_leaf {
                    let (code, _, capacity) = by_leaf[&leaf];
                    let sum = held.entry(leaf).or_insert(0);
                    *sum = sum
                        .checked_add(amount)
                        .ok_or(fa_registers::RegisterError::Overflow)?;
                    let item = Part370PendingItem {
                        dp_acct_id: code.to_string(),
                        pending_id: pending_id.clone(),
                        pd_right_capacity: Some(capacity.to_string()),
                        hold_reason: proposal
                            .description
                            .open(&book.seal_key, limits::MAX_DESCRIPTION_BYTES)
                            .unwrap_or_default(),
                        unit_code: "USD".into(),
                        scale: 2,
                        amount_mantissa: amount,
                        effective_date: proposal.effective_date,
                    };
                    if items.insert((leaf, pending_id.clone()), item).is_some() {
                        return Ok(Err(incomplete(
                            format!(
                                "two open holds on deposit `{code}` share the id `{pending_id}`; Part 370 names each pending item once"
                            ),
                            "give each hold on a deposit its own idempotency key",
                        )));
                    }
                }
            }
            let pending: Vec<Part370PendingItem> = items.into_values().collect();
            for account in &accounts {
                let leaf = deposits
                    .iter()
                    .find(|d| d.code == account.dp_acct_id)
                    .map(|d| d.mirrors_account)
                    .ok_or_else(|| KernelError::Corrupt("a deposit vanished".into()))?;
                let listed = held.get(&leaf).copied().unwrap_or(0);
                if listed != account.hold_amount_mantissa {
                    return Err(KernelError::Corrupt(format!(
                        "deposit `{}`: open holds sum to {listed} but its leaf's pending debits are {}",
                        account.dp_acct_id, account.hold_amount_mantissa
                    ))
                    .into());
                }
            }
            Ok(Ok((
                at,
                accounts,
                participants,
                customers,
                pending,
            )))
        })?;
        let (at, accounts, participants, customers, pending_items) = match built {
            Ok(parts) => parts,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let coordinate = self.format_journal(cx, as_of, Some(at))?.coordinate;
        Ok(Ok(Part370BankBook {
            coordinate,
            effective_date: as_of,
            sdia_mantissa: FDIC_SDIA_USD_CENTS,
            customers,
            accounts,
            participants,
            pending_items,
        }))
    }
}
