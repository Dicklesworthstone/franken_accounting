//! Declared three-way source profiles for retained purchase orders, receiving
//! reports and invoices. These readers interpret the exact supplied CSV bytes;
//! they do not authenticate the source, infer fields, or approve a payment.
//!
//! Version 1 uses whole, nonnegative item counts and exact nonnegative prices.
//! Each source carries at most one line per exact item identifier. A repeated
//! item is ambiguous and refuses the complete source, including when another
//! item was requested. Partial receipts and invoices remain visible as quantity
//! variances; this profile does not silently aggregate or prorate them.

use std::collections::BTreeSet;

use fa_model::{Oid, limits};
use fa_money::{Amount, UnitKind, UnitRegistry};
use fa_registers::reconciliation::{PurchaseOrderLine, ReceivingReportLine, VendorInvoiceLine};
use fa_registry::evidence_policy::EvidencePolicy;

use crate::{FormatError, UnitCatalog, hex_decode, parse_exact_decimal};

pub const THREE_WAY_PROFILE: &str = "fa_three_way_csv_v1";
/// The existing atomic evidence intake bound also bounds each source's lines.
pub const MAX_THREE_WAY_LINES: usize = limits::MAX_IMPORT_DOCUMENTS;

pub const PURCHASE_ORDER_HEADER: &str = "vendor,item_code,quantity,unit_price,currency";
pub const RECEIVING_REPORT_HEADER: &str = "purchase_order_oid,item_code,quantity_received";
pub const INVOICE_HEADER: &str =
    "purchase_order_oid,vendor,item_code,quantity_billed,unit_price_billed,total_billed,currency";

/// One-based data-record ordinal, excluding the header. Embedded CSV newlines
/// never change the ordinal; it identifies a parsed record, not a text line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWaySourceLine<T> {
    pub ordinal: u32,
    pub line: T,
}

fn invalid(detail: impl Into<String>) -> FormatError {
    FormatError::Parse {
        format: THREE_WAY_PROFILE,
        detail: detail.into(),
    }
}

fn records(csv: &str, header: &str) -> Result<Vec<Vec<String>>, FormatError> {
    let byte_limit = EvidencePolicy::embedded()
        .map_err(|error| invalid(error.to_string()))?
        .max_document_bytes;
    if u64::try_from(csv.len()).map_or(true, |size| size > byte_limit) {
        return Err(invalid(format!(
            "source exceeds evidence_policy.max_document_bytes={byte_limit}"
        )));
    }
    let columns: Vec<_> = header.split(',').collect();
    let rows = crate::bank::bank_csv_records_with(
        csv,
        ',',
        columns.len(),
        MAX_THREE_WAY_LINES + 1,
        THREE_WAY_PROFILE,
    )?;
    let mut rows = rows.into_iter();
    let actual = rows
        .next()
        .ok_or_else(|| invalid("source has no CSV header"))?;
    if actual.iter().map(String::as_str).collect::<Vec<_>>() != columns {
        return Err(invalid(format!(
            "expected the exact ordered header {header:?}"
        )));
    }
    let mut result = Vec::new();
    for (index, row) in rows.enumerate() {
        if row.len() != columns.len() {
            return Err(invalid(format!(
                "data record {} has {} fields; the declared header has {}",
                index + 1,
                row.len(),
                columns.len()
            )));
        }
        result.push(row);
    }
    if result.is_empty() {
        return Err(invalid("source must carry at least one data record"));
    }
    Ok(result)
}

fn identifier<'a>(value: &'a str, name: &str) -> Result<&'a str, FormatError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > limits::MAX_EXTERNAL_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "{name} must be a nonempty exact identifier of at most {} bytes, without surrounding whitespace or control characters",
            limits::MAX_EXTERNAL_ID_BYTES
        )));
    }
    Ok(value)
}

fn item(value: &str, seen: &mut BTreeSet<String>) -> Result<String, FormatError> {
    let value = identifier(value, "item_code")?;
    if !seen.insert(value.to_owned()) {
        return Err(invalid(format!(
            "duplicate item_code {value:?}; {THREE_WAY_PROFILE} requires one unambiguous line per item in each source"
        )));
    }
    Ok(value.to_owned())
}

fn quantity(value: &str) -> Result<i128, FormatError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid(
            "quantity must be a canonical nonnegative whole count (digits only, no sign, decimal, exponent or leading zero)",
        ));
    }
    value
        .parse()
        .map_err(|_| invalid("quantity exceeds the exact i128 count range"))
}

fn price(
    value: &str,
    currency: &str,
    units: &UnitCatalog,
    registry: &UnitRegistry,
) -> Result<Amount, FormatError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(invalid(
            "price and total fields must be nonnegative exact decimals, without signs, grouping, exponents or whitespace",
        ));
    }
    let (unit, scale) = units
        .lookup_code(currency)
        .ok_or_else(|| FormatError::UnknownUnit {
            format: THREE_WAY_PROFILE,
            unit: currency.to_owned(),
        })?;
    if registry
        .get(unit)
        .is_none_or(|row| !matches!(row.kind, UnitKind::Currency { .. }))
    {
        return Err(invalid("currency must name a registered Currency unit"));
    }
    Ok(Amount::new(
        unit,
        parse_exact_decimal(THREE_WAY_PROFILE, value, scale)?,
    ))
}

fn purchase_order_oid(value: &str) -> Result<Oid, FormatError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "purchase_order_oid must be the full 64-digit retained document OID, without a D: prefix or whitespace",
        ));
    }
    hex_decode(THREE_WAY_PROFILE, value).map(Oid)
}

fn ordinal(index: usize) -> Result<u32, FormatError> {
    u32::try_from(index + 1).map_err(|_| invalid("source line ordinal exceeds u32"))
}

/// Parse every line of a PurchaseOrder source. `oid` is supplied by the
/// authenticated document reader, never read from the document's own text.
pub fn parse_purchase_order_csv(
    csv: &str,
    oid: Oid,
    units: &UnitCatalog,
) -> Result<Vec<ThreeWaySourceLine<PurchaseOrderLine>>, FormatError> {
    let mut seen = BTreeSet::new();
    let registry = UnitRegistry::embedded().map_err(|error| invalid(error.to_string()))?;
    records(csv, PURCHASE_ORDER_HEADER)?
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(ThreeWaySourceLine {
                ordinal: ordinal(index)?,
                line: PurchaseOrderLine {
                    po_oid: oid,
                    vendor: identifier(&row[0], "vendor")?.to_owned(),
                    item_code: item(&row[1], &mut seen)?,
                    quantity: quantity(&row[2])?,
                    unit_price: price(&row[3], &row[4], units, &registry)?,
                },
            })
        })
        .collect()
}

/// Parse every line of a ReceivingReport source; its reference names the
/// exact retained PurchaseOrder, not a caller's display label.
pub fn parse_receiving_report_csv(
    csv: &str,
    oid: Oid,
) -> Result<Vec<ThreeWaySourceLine<ReceivingReportLine>>, FormatError> {
    let mut seen = BTreeSet::new();
    records(csv, RECEIVING_REPORT_HEADER)?
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(ThreeWaySourceLine {
                ordinal: ordinal(index)?,
                line: ReceivingReportLine {
                    receipt_oid: oid,
                    po_oid: purchase_order_oid(&row[0])?,
                    item_code: item(&row[1], &mut seen)?,
                    quantity_received: quantity(&row[2])?,
                },
            })
        })
        .collect()
}

/// Parse every line of an Invoice source. The source's stated total remains
/// independent of quantity × price so an extension error remains observable.
pub fn parse_invoice_csv(
    csv: &str,
    oid: Oid,
    units: &UnitCatalog,
) -> Result<Vec<ThreeWaySourceLine<VendorInvoiceLine>>, FormatError> {
    let mut seen = BTreeSet::new();
    let registry = UnitRegistry::embedded().map_err(|error| invalid(error.to_string()))?;
    records(csv, INVOICE_HEADER)?
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            Ok(ThreeWaySourceLine {
                ordinal: ordinal(index)?,
                line: VendorInvoiceLine {
                    invoice_oid: oid,
                    po_oid: purchase_order_oid(&row[0])?,
                    vendor: identifier(&row[1], "vendor")?.to_owned(),
                    item_code: item(&row[2], &mut seen)?,
                    quantity_billed: quantity(&row[3])?,
                    unit_price_billed: price(&row[4], &row[6], units, &registry)?,
                    total_billed: price(&row[5], &row[6], units, &registry)?,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_registers::reconciliation::{ThreeWayMatchVerdict, match_three_way};

    #[test]
    fn retained_profiles_preserve_exact_prices_references_and_independent_totals() {
        let units = UnitCatalog::embedded().unwrap();
        let po_oid = Oid([1; 32]);
        let po_text = format!("{PURCHASE_ORDER_HEADER}\r\n\"Vendor, Inc.\",SKU-1,3,12.34,USD\r\n");
        let receipt_text = format!(
            "{RECEIVING_REPORT_HEADER}\n{},SKU-1,3\n",
            crate::hex_encode(&po_oid.0)
        );
        let invoice_text = format!(
            "{INVOICE_HEADER}\n{},\"Vendor, Inc.\",SKU-1,3,12.34,37.01,USD\n",
            crate::hex_encode(&po_oid.0)
        );
        let po = parse_purchase_order_csv(&po_text, po_oid, &units).unwrap();
        let receipt = parse_receiving_report_csv(&receipt_text, Oid([2; 32])).unwrap();
        let invoice = parse_invoice_csv(&invoice_text, Oid([3; 32]), &units).unwrap();
        assert_eq!(po[0].ordinal, 1);
        assert_eq!(po[0].line.vendor, "Vendor, Inc.");
        assert_eq!(po[0].line.unit_price.mantissa, 1_234);
        assert_eq!(receipt[0].line.po_oid, po_oid);
        assert_eq!(invoice[0].line.total_billed.mantissa, 3_701);
        let result = match_three_way(
            &po[0].line,
            &receipt[0].line,
            &invoice[0].line,
            None,
            [4; 32],
        )
        .unwrap();
        assert!(matches!(
            result.verdict,
            ThreeWayMatchVerdict::ExtensionMismatch { expected_total, invoice_total }
                if expected_total.mantissa == 3_702 && invoice_total.mantissa == 3_701
        ));
    }

    #[test]
    fn profile_rejects_ambiguous_or_malformed_sources_in_full() {
        let units = UnitCatalog::embedded().unwrap();
        let po = Oid([1; 32]);
        for body in [
            "Vendor,SKU,1,2.00,USD\nVendor,SKU,1,2.00,USD\n",
            "Vendor,SKU,1,2.00,USD\nVendor,OTHER,1,1e2,USD\n",
            "Vendor,SKU,1,2.001,USD\n",
            "Vendor,SKU,-1,2.00,USD\n",
            "Vendor,SKU,1.5,2.00,USD\n",
            "Vendor,SKU,01,2.00,USD\n",
            "Vendor,SKU,170141183460469231731687303715884105728,2.00,USD\n",
            "Vendor,SKU,1,2.00,UNKNOWN\n",
            "Vendor,SKU,1,2.00,USD,unexpected\n",
            "Vendor,SKU,1,2.00\n",
            " Vendor,SKU,1,2.00,USD\n",
            "Vendor,,1,2.00,USD\n",
            "\"Vendor\"trailing,SKU,1,2.00,USD\n",
        ] {
            assert!(
                parse_purchase_order_csv(&format!("{PURCHASE_ORDER_HEADER}\n{body}"), po, &units)
                    .is_err(),
                "accepted {body:?}"
            );
        }
        assert!(parse_purchase_order_csv(PURCHASE_ORDER_HEADER, po, &units).is_err());
        assert!(
            parse_purchase_order_csv(
                "vendor,item_code,quantity,currency,unit_price\nVendor,SKU,1,USD,2.00\n",
                po,
                &units
            )
            .is_err()
        );
        assert!(
            parse_receiving_report_csv(
                &format!("{RECEIVING_REPORT_HEADER}\nnot-a-document,SKU,1\n"),
                Oid([2; 32])
            )
            .is_err()
        );
    }

    #[test]
    fn source_line_bound_is_inclusive_and_never_truncates() {
        let units = UnitCatalog::embedded().unwrap();
        let mut source = format!("{PURCHASE_ORDER_HEADER}\n");
        for i in 0..MAX_THREE_WAY_LINES {
            source.push_str(&format!("Vendor,SKU-{i},0,0,USD\n"));
        }
        let parsed = parse_purchase_order_csv(&source, Oid([1; 32]), &units).unwrap();
        assert_eq!(parsed.len(), MAX_THREE_WAY_LINES);
        assert_eq!(parsed.last().unwrap().ordinal, MAX_THREE_WAY_LINES as u32);
        source.push_str("Vendor,ONE-TOO-MANY,0,0,USD\n");
        assert!(parse_purchase_order_csv(&source, Oid([1; 32]), &units).is_err());
    }
}
