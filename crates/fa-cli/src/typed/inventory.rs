//! A typed sales invoice and its independently derived lot relief, retained as
//! one ordinary PostBatch. Costing, source witnesses and promotion stay in the
//! native disposal and batch protocols.

use std::collections::{BTreeMap, BTreeSet};

use fa::{Book, LotDisposalPostRequest, PostBatch, PostIntent};
use fa_model::lot_disposal::LotDisposalBasis;
use fa_model::{Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, Id128, Oid, account_vid};
use fa_money::{Amount, LotLaw, UnitKind};
use fa_policy::{Capability, Op, Reach};
use fgdb_types::VId;

use crate::cli::{Fail, hex, parse_vid, usage};

pub(super) const LINE_FIELDS: &[&str] = &[
    "inventory",
    "quantity_unit",
    "quantity_offset",
    "cost_offset",
    "lot_law",
    "lots",
];

const EXAMPLE: &str = "fa invoice --party CUSTOMER --number INV-1 --date YYYY-MM-DD --receivable 1200 --revenue 4000 --line 'qty=3 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1490 cost_offset=5100 lot_law=FIFO' --evidence D:<oid> --dry-run --json; SpecificId additionally requires lots=<entry-vid>:<quantity-leg-ordinal>[,...]";

#[derive(Clone, Debug)]
pub(super) struct LineRelief {
    line_index: usize,
    quantity: String,
    inventory: String,
    quantity_unit: String,
    quantity_offset: String,
    cost_offset: String,
    law: LotLaw,
    targets: Vec<(VId, u16)>,
}

/// Parse only declared inventory inputs. The ordinary invoice parser retains
/// ownership of price, currency, account, description and maturity semantics.
pub(super) fn parse_line(
    words: &[(String, String)],
    line_index: usize,
    is_invoice: bool,
) -> Result<Option<LineRelief>, Fail> {
    if !words
        .iter()
        .any(|(name, _)| LINE_FIELDS.contains(&name.as_str()))
    {
        return Ok(None);
    }
    let ordinal = line_index
        .checked_add(1)
        .ok_or_else(|| usage("invoice line index is too large", EXAMPLE))?;
    let fail = |message: String| usage(format!("--line {ordinal}: {message}"), EXAMPLE);
    if !is_invoice {
        return Err(fail(
            "inventory relief belongs to sales invoices, not bills".into(),
        ));
    }
    let field = |name: &str| {
        words
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    };
    for name in LINE_FIELDS {
        if words
            .iter()
            .filter(|(candidate, _)| candidate.as_str() == *name)
            .count()
            > 1
        {
            return Err(fail(format!("{name} may appear only once")));
        }
    }
    let required = |name: &str| {
        field(name)
            .filter(|value| !value.is_empty() && value.trim() == *value)
            .ok_or_else(|| fail(format!("inventory relief requires a nonempty {name}")))
    };
    let quantity = required("qty")?;
    required("unit_price")?;
    if field("amount").is_some() {
        return Err(fail(
            "an inventory line uses qty and unit_price, not an independent amount".into(),
        ));
    }
    let law_name = required("lot_law")?;
    let law = LotLaw::from_name(law_name).ok_or_else(|| {
        fail(format!(
            "unknown lot_law {law_name}; use FIFO, LIFO, SpecificId or WeightedAverage"
        ))
    })?;
    let mut targets = Vec::new();
    match (law, field("lots")) {
        (LotLaw::SpecificId, Some(raw)) if !raw.is_empty() => {
            let mut seen = BTreeSet::new();
            for selector in raw.split(',') {
                if targets.len() == fa_model::lot_disposal::MAX_SPECIFIC_LOTS {
                    return Err(fail(format!(
                        "lots exceeds max_specific_lots={}",
                        fa_model::lot_disposal::MAX_SPECIFIC_LOTS
                    )));
                }
                let (vid, ordinal) = selector.rsplit_once(':').ok_or_else(|| {
                    fail("lots requires entry-vid:quantity-leg-ordinal selectors".into())
                })?;
                let vid = parse_vid(vid, "lots")?;
                let ordinal = ordinal
                    .parse::<u16>()
                    .map_err(|_| fail("lots contains an invalid quantity-leg ordinal".into()))?;
                if !seen.insert((vid, ordinal)) {
                    return Err(fail("lots repeats an acquisition quantity leg".into()));
                }
                targets.push((vid, ordinal));
            }
        }
        (LotLaw::SpecificId, _) => {
            return Err(fail(
                "SpecificId requires an explicit nonempty lots selection".into(),
            ));
        }
        (_, Some(_)) => {
            return Err(fail("lots is valid only with lot_law=SpecificId".into()));
        }
        (_, None) => {}
    }
    Ok(Some(LineRelief {
        line_index,
        quantity: quantity.into(),
        inventory: required("inventory")?.into(),
        quantity_unit: required("quantity_unit")?.into(),
        quantity_offset: required("quantity_offset")?.into(),
        cost_offset: required("cost_offset")?.into(),
        law,
        targets,
    }))
}

#[derive(Clone, Debug)]
struct Group {
    request: LotDisposalPostRequest,
    law: LotLaw,
    targets: Vec<(VId, u16)>,
}

impl Group {
    fn compatible(&self, other: &Self) -> bool {
        self.request.account == other.request.account
            && self.request.dimensions == other.request.dimensions
            && self.request.quantity.unit == other.request.quantity.unit
            && self.request.quantity_offset_account == other.request.quantity_offset_account
            && self.request.cost_offset_account == other.request.cost_offset_account
            && self.law == other.law
            && self.targets == other.targets
    }

    fn matches_basis(&self, basis: &LotDisposalBasis) -> bool {
        self.request.account == basis.account
            && self.request.dimensions == basis.dimensions
            && self.request.quantity == basis.quantity
            && self.request.quantity_offset_account == basis.quantity_offset_account
            && self.request.cost_offset_account == basis.cost_offset_account
            && self.law == basis.law
            && self.targets.len() == basis.specific_ids.len()
            && self.targets.iter().zip(&basis.specific_ids).all(
                |((vid, ordinal), (target, target_ordinal))| {
                    *vid == target.vid && ordinal == target_ordinal
                },
            )
    }
}

fn group_lines(
    book: &Book,
    invoice: &EntryPayload,
    relief: &[LineRelief],
) -> Result<Vec<Group>, Fail> {
    let mut grouped = BTreeMap::<VId, Group>::new();
    for line in relief {
        let ordinal = line
            .line_index
            .checked_add(1)
            .ok_or_else(|| usage("invoice line index is too large", EXAMPLE))?;
        let leg = invoice
            .legs
            .get(ordinal)
            .ok_or_else(|| Fail::Internal("inventory line lost its ordinary invoice leg".into()))?;
        let quantity = Amount::parse(
            &format!("{} {}", line.quantity, line.quantity_unit),
            &book.context().units,
        )
        .map_err(|error| usage(format!("--line {ordinal}: inventory qty: {error}"), EXAMPLE))?;
        if quantity.mantissa <= 0
            || book.context().units.get(quantity.unit).is_none_or(|unit| {
                matches!(unit.kind, UnitKind::Currency { .. }) || unit.allows_single_sided()
            })
        {
            return Err(usage(
                format!(
                    "--line {ordinal}: inventory qty must be positive in a balanced noncurrency quantity_unit"
                ),
                EXAMPLE,
            ));
        }
        let account = account_vid(invoice.book_id, &line.inventory);
        let group = Group {
            request: LotDisposalPostRequest {
                account,
                dimensions: leg.dimension_set.clone(),
                quantity,
                quantity_offset_account: account_vid(invoice.book_id, &line.quantity_offset),
                cost_offset_account: account_vid(invoice.book_id, &line.cost_offset),
                specific_ids: Vec::new(),
            },
            law: line.law,
            targets: line.targets.clone(),
        };
        if let Some(previous) = grouped.get_mut(&account) {
            if !previous.compatible(&group) {
                return Err(usage(
                    format!(
                        "--line {ordinal}: repeated inventory account {} has different units, dimensions, offsets, law or ordered lots",
                        line.inventory
                    ),
                    "one atomic invoice derives one disposal per inventory account; repeat only identical relief selections, or use separate source accounts for distinct partitions",
                ));
            }
            previous.request.quantity = previous
                .request
                .quantity
                .checked_add(quantity)
                .map_err(|error| usage(format!("combined invoice quantity: {error}"), EXAMPLE))?;
        } else {
            grouped.insert(account, group);
        }
    }
    if grouped.is_empty() || grouped.len() >= fa_model::limits::MAX_BATCH_ENTRIES {
        return Err(usage(
            "an inventory invoice needs a bounded nonempty set of lot sources",
            EXAMPLE,
        ));
    }
    Ok(grouped.into_values().collect())
}

fn derived_key(invoice: &EntryPayload, account: Option<VId>) -> Vec<u8> {
    let digest = match account {
        Some(account) => fa_model::domain_digest(
            b"fa:invoice-lot-relief:key:v1",
            &[
                &invoice.book_id.0,
                &invoice.principal_ref.0.to_le_bytes(),
                &invoice.idempotency_key,
                &account.0.to_le_bytes(),
            ],
        ),
        None => fa_model::domain_digest(
            b"fa:invoice-lot-batch:key:v1",
            &[
                &invoice.book_id.0,
                &invoice.principal_ref.0.to_le_bytes(),
                &invoice.idempotency_key,
            ],
        ),
    };
    // The ordinary batch receipt can display these keys as UTF-8, and neither
    // a long user key nor a suffix can exceed the native 64-byte key bound.
    hex(&digest).into_bytes()
}

fn template(invoice: &EntryPayload, account: VId) -> EntryPayload {
    let key = derived_key(invoice, Some(account));
    EntryPayload {
        schema_minor: invoice.schema_minor,
        book_id: invoice.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: invoice.effective_date,
        document_date: invoice.document_date,
        description: invoice.description.clone(),
        effective_period: invoice.effective_period.clone(),
        legs: Vec::new(),
        control: None,
        unit_totals: Vec::new(),
        base_totals: None,
        origin: EntryOrigin::Intent {
            intent_oid: Oid(fa_model::domain_digest(
                b"fa:intent:v1",
                &[
                    &invoice.book_id.0,
                    &invoice.principal_ref.0.to_le_bytes(),
                    &key,
                ],
            )),
            intent_kind: 1,
        },
        idempotency_key: key,
        principal_ref: invoice.principal_ref,
        session_ref: invoice.session_ref,
        evidence: invoice.evidence.clone(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        tags: invoice.tags.clone(),
        // Receivable maturity and other invoice-only extensions belong only
        // to the invoice. The native factory installs its own complete basis.
        extensions: Vec::new(),
    }
}

fn retry_conflict() -> Fail {
    fa_journal::Refusal::new(
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT,
        fa_journal::exit::CONFLICT,
        "this invoice key already has different retained lot-relief inputs or evidence",
        "plan §4.9 / §5.8 / §6.5 (unchanged reviewed invoice and native lot relief)",
        "retry the complete original invoice unchanged, or use a new invoice key for new content",
    )
    .into()
}

/// A retained native Original disposal is already the exact proposal the
/// draft reviewed. Check every new declared selection and template field;
/// reuse its original sealed bytes and basis only after that comparison.
fn retained_disposal(
    book: &Book,
    group: &Group,
    mut expected: EntryPayload,
    retained: &Entry,
) -> Result<PostIntent, Fail> {
    let proposal = &retained.proposal;
    let basis = proposal
        .lot_disposal_basis()
        .map_err(|_| retry_conflict())?
        .ok_or_else(retry_conflict)?;
    if !retained.approvals.is_empty()
        || proposal.class != EntryClass::ORIGINAL
        || proposal.extensions.len() != 1
        || proposal.base_totals.is_some()
        || proposal.control.is_some()
        || proposal.pending.is_some()
        || !proposal.supersession.is_empty()
        || !group.matches_basis(&basis)
    {
        return Err(retry_conflict());
    }
    expected.legs = proposal.legs.clone();
    expected.unit_totals = proposal.unit_totals.clone();
    expected
        .set_lot_disposal_basis(&basis)
        .map_err(|_| retry_conflict())?;
    let same = expected == *proposal
        || match (
            expected.semantic_digest(&book.context().seal_key),
            proposal.semantic_digest(&book.context().seal_key),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        };
    if !same {
        return Err(retry_conflict());
    }
    PostIntent::new(proposal.clone(), Vec::new())
        .map_err(|error| Fail::Internal(format!("retained invoice disposal: {error}")))
}

/// Compose a native-cost sales invoice. The caller has built its ordinary
/// invoice through the existing parser; publication and current generated
/// effect admission remain with the existing batch/plan/draft entry points.
pub(super) fn prepare(
    book: &mut Book,
    capability: &Capability,
    draft: Option<&str>,
    invoice: &PostIntent,
    relief: &[LineRelief],
) -> Result<PostBatch, Fail> {
    book.admit_current(capability)??;
    let original = invoice.proposal();
    if original.book_id != book.context().book_id
        || original.principal_ref != capability.holder()
        || original.branch_id != Id128::TRUNK
        || original.class != EntryClass::ORIGINAL
        || original.control.is_some()
        || original.pending.is_some()
        || !original.supersession.is_empty()
        || !invoice.approvals().is_empty()
        || original.legs.iter().any(|leg| !leg.settles.is_empty())
    {
        return Err(usage(
            "inventory relief requires an ordinary unapproved sales invoice without applications",
            EXAMPLE,
        ));
    }
    let retained = match draft {
        Some(name) => book.draft_entries(capability, name)??,
        None => Vec::new(),
    };
    let confined_draft = draft.filter(|_| capability.branch().is_some());
    if confined_draft.is_none() {
        fa_policy::admit_read(capability, capability.holder(), original.book_id)
            .and_then(|()| fa_policy::require(capability, Op::Post, "preparing inventory invoices"))
            .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(capability.holder(), capability)??
            .admit_whole_book(None)??;
    }
    let groups = group_lines(book, original, relief)?;
    let mut members = Vec::with_capacity(groups.len() + 1);
    members.push(invoice.clone());
    for group in groups {
        let template = template(original, group.request.account);
        if let Some(prior) = retained
            .iter()
            .find(|entry| entry.proposal.idempotency_key == template.idempotency_key)
        {
            members.push(retained_disposal(book, &group, template, prior)?);
            continue;
        }
        let mut request = group.request.clone();
        let prepared = match confined_draft {
            Some(name) => book.prepare_lot_disposal_targets_in_draft(
                capability,
                name,
                &request,
                &group.targets,
                template,
            )??,
            None => {
                for &(vid, ordinal) in &group.targets {
                    let (entry, _) = book
                        .read_scope(capability.holder(), capability)??
                        .read_entry(vid, None)??
                        .ok_or_else(|| {
                            usage("a selected invoice lot entry does not exist", EXAMPLE)
                        })?;
                    request.specific_ids.push((
                        EntryRef {
                            vid,
                            entry_digest: entry.entry_digest,
                        },
                        ordinal,
                    ));
                }
                book.prepare_lot_disposal(capability, &request, template)??
            }
        };
        if prepared.basis().law != group.law {
            return Err(usage(
                format!(
                    "invoice lot_law={} differs from the retained account policy {}",
                    group.law.name(),
                    prepared.basis().law.name()
                ),
                "select the account's retained lot law; changing its law requires the ordinary reviewed lot-policy transition",
            ));
        }
        members.push(
            PostIntent::new(prepared.into_proposal(), Vec::new())
                .map_err(|error| usage(format!("invoice lot relief: {error}"), EXAMPLE))?,
        );
    }
    PostBatch::new(derived_key(original, None), members)
        .map_err(|error| usage(format!("inventory invoice batch: {error}"), EXAMPLE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stock_fields() -> Vec<(String, String)> {
        [
            ("qty", "3"),
            ("unit_price", "25.00 USD"),
            ("inventory", "1400"),
            ("quantity_unit", "SHARE"),
            ("quantity_offset", "1490"),
            ("cost_offset", "5100"),
            ("lot_law", "FIFO"),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect()
    }

    #[test]
    fn inventory_lines_require_a_complete_explicit_contract_and_sales_quantity() {
        let words = stock_fields();
        let parsed = parse_line(&words, 2, true)
            .unwrap_or_else(|_| panic!("complete inventory line refused"))
            .unwrap();
        assert_eq!(parsed.line_index, 2);
        assert_eq!(parsed.quantity, "3");
        assert_eq!(parsed.law, LotLaw::Fifo);
        assert!(parse_line(&words, 0, false).is_err());
        for missing in LINE_FIELDS.iter().copied().filter(|name| *name != "lots") {
            let reduced: Vec<_> = words
                .iter()
                .filter(|(name, _)| name != missing)
                .cloned()
                .collect();
            assert!(parse_line(&reduced, 0, true).is_err(), "{missing}");
        }
        for missing in ["qty", "unit_price"] {
            let reduced: Vec<_> = words
                .iter()
                .filter(|(name, _)| name != missing)
                .cloned()
                .collect();
            assert!(parse_line(&reduced, 0, true).is_err(), "{missing}");
        }
        let mut amount = words;
        amount.push(("amount".into(), "75.00 USD".into()));
        assert!(parse_line(&amount, 0, true).is_err());
        assert!(
            parse_line(&[("amount".into(), "75.00 USD".into())], 0, true)
                .unwrap_or_else(|_| panic!("ordinary service line refused"))
                .is_none()
        );
    }

    #[test]
    fn specific_id_keeps_order_and_rejects_duplicate_or_unrequested_lots() {
        let mut fields = stock_fields();
        fields.push((
            "lots".into(),
            "00000000000000000000000000000002:3,00000000000000000000000000000001:0".into(),
        ));
        assert!(parse_line(&fields, 0, true).is_err());
        fields
            .iter_mut()
            .find(|(name, _)| name == "lot_law")
            .unwrap()
            .1 = "SpecificId".into();
        let parsed = parse_line(&fields, 0, true)
            .unwrap_or_else(|_| panic!("ordered SpecificId selection refused"))
            .unwrap();
        assert_eq!(parsed.targets, vec![(VId(2), 3), (VId(1), 0)]);
        fields.last_mut().unwrap().1 =
            "00000000000000000000000000000001:0,00000000000000000000000000000001:0".into();
        assert!(parse_line(&fields, 0, true).is_err());
        fields.pop();
        assert!(parse_line(&fields, 0, true).is_err());
    }
}
