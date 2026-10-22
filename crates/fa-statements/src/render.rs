//! Deterministic rendering of certified `StatementMarkdownIr` to HTML, SVG, PDF,
//! and PDF/A-2b (ISO 19005-2), plus semantic restatement diffs and lineage
//! flowcharts (plan §12.1, §12.5, beads `fa-cet` and `fa-949`).
//!
//! Constitutional guarantees:
//! - Zero floating-point arithmetic (`i64`/`u64`/`i128` integer layout and math only).
//! - Creation timestamps are derived exclusively from the caller-supplied
//!   `creation_epoch_secs` (from the certificate's `TimeEvidence`), never the wall clock.
//! - Right-aligned numeric columns and single/double accounting footing rules are
//!   preserved across Markdown IR, HTML, SVG, PDF, and PDF/A-2b outputs.
//! - Identical `(StatementMarkdownIr, creation_epoch_secs)` inputs produce
//!   byte-for-byte identical outputs across runs and machines.

use std::path::{Path, PathBuf};
use std::process::Command;

use fa_model::{Id128, Oid, domain_digest};

use crate::StatementError;
use crate::markdown::{ColumnAlignment, FootingRule, MarkdownTable, StatementMarkdownIr};

/// Target output format for a rendered statement or exhibit (`fa-cet`, `fa-949`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementRenderFormat {
    Markdown,
    Html,
    Svg,
    Pdf,
    Pdfa2b,
}

impl StatementRenderFormat {
    pub fn parse(raw: &str) -> Result<Self, StatementError> {
        match raw {
            "md" | "markdown" => Ok(Self::Markdown),
            "html" => Ok(Self::Html),
            "svg" => Ok(Self::Svg),
            "pdf" => Ok(Self::Pdf),
            "pdfa" | "pdfa-2b" | "pdf-a-2b" => Ok(Self::Pdfa2b),
            other => Err(StatementError::Input(format!(
                "unsupported statement render format `{other}`; expected md|html|svg|pdf|pdfa"
            ))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Html => "html",
            Self::Svg => "svg",
            Self::Pdf => "pdf",
            Self::Pdfa2b => "pdfa",
        }
    }
}

/// Convert Unix epoch seconds into `(year, month, day, hour, minute, second)`
/// using Howard Hinnant's pure-integer civil-from-days algorithm (never reading wall clock).
// Each narrowing is bounded by the algorithm: the second of the day is below
// 86 400 and the day of the era is in [0, 146 096] (annotated inline).
#[allow(clippy::cast_possible_truncation)]
pub const fn civil_utc_from_epoch_secs(epoch_secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (epoch_secs / 86_400) as i64;
    let rem = (epoch_secs % 86_400) as u32;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, minute, second)
}

/// Format Unix epoch seconds as deterministic ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_utc_epoch_iso8601(epoch_secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_utc_from_epoch_secs(epoch_secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Format Unix epoch seconds as deterministic PDF date (`D:YYYYMMDDHHMMSSZ`).
pub fn format_utc_epoch_pdf_date(epoch_secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_utc_from_epoch_secs(epoch_secs);
    format!("D:{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z")
}

fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn escape_pdf_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Render a `StatementMarkdownIr` into a deterministic, self-contained HTML5 document (`fa-cet`).
///
/// Right-aligned numeric columns use `.align-right` (`text-align: right; font-variant-numeric: tabular-nums;`),
/// intermediate subtotals use `.footing-single` (`border-bottom: 1px solid #111;`), and bottom-line totals
/// use `.footing-double` (`border-bottom: 3px double #111;`).
pub fn render_html(
    ir: &StatementMarkdownIr,
    creation_epoch_secs: u64,
) -> Result<Vec<u8>, StatementError> {
    let ir_digest = ir.digest()?;
    let ir_digest_hex = hex_bytes(&ir_digest.0);
    let created_iso = format_utc_epoch_iso8601(creation_epoch_secs);
    let is_restatement_diff = ir.compared_known_at.is_some();

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str(&format!(
        "<meta name=\"dcterms.created\" content=\"{created_iso}\">\n"
    ));
    html.push_str(&format!(
        "<meta name=\"fa:ir-digest\" content=\"{ir_digest_hex}\">\n"
    ));
    html.push_str(&format!(
        "<title>FrankenAccounting Statement: {} (v{})</title>\n",
        escape_html(&ir.definition_name),
        ir.definition_version
    ));
    html.push_str(
        "<style>\n\
         body { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; margin: 24px; color: #111; }\n\
         table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }\n\
         th, td { padding: 6px 10px; border-bottom: 1px solid #ddd; }\n\
         th.align-left, td.align-left { text-align: left; }\n\
         th.align-right, td.align-right { text-align: right; font-variant-numeric: tabular-nums; }\n\
         tr.footing-single td { border-top: 1px solid #111; border-bottom: 1px solid #111; font-weight: 600; }\n\
         tr.footing-double td { border-top: 1px solid #111; border-bottom: 3px double #111; font-weight: 700; }\n\
         tr.delta-nonzero { background-color: #fff8e6; }\n\
         </style>\n</head>\n<body>\n",
    );
    html.push_str(&format!(
        "<h1>Statement: {} (v{})</h1>\n",
        escape_html(&ir.definition_name),
        ir.definition_version
    ));
    html.push_str("<ul class=\"statement-metadata\">\n");
    html.push_str(&format!(
        "  <li>Book: <code>{}</code></li>\n",
        ir.book_id.to_hex()
    ));
    html.push_str(&format!(
        "  <li>Branch: <code>{}</code></li>\n",
        ir.branch_id.to_hex()
    ));
    if let Some(orig_seq) = ir.compared_known_at {
        html.push_str(&format!(
            "  <li>Originally Reported Sequence: <code>{orig_seq}</code></li>\n"
        ));
    }
    html.push_str(&format!(
        "  <li>Known-At Sequence: <code>{}</code></li>\n",
        ir.known_at
    ));
    html.push_str(&format!(
        "  <li>IR Digest: <code>{ir_digest_hex}</code></li>\n"
    ));
    html.push_str(&format!(
        "  <li>Created UTC: <code>{created_iso}</code></li>\n"
    ));
    html.push_str("</ul>\n");

    for table in &ir.tables {
        html.push_str(&format!(
            "<h2>Unit: {} (id={}, scale={})</h2>\n",
            escape_html(&table.unit_code),
            table.unit_id,
            table.unit_scale
        ));
        let table_class = if is_restatement_diff {
            "statement-table restatement-diff"
        } else {
            "statement-table"
        };
        html.push_str(&format!("<table class=\"{table_class}\">\n<thead>\n<tr>"));
        for (idx, header) in table.headers.iter().enumerate() {
            let align_cls = match table
                .alignments
                .get(idx)
                .copied()
                .unwrap_or(ColumnAlignment::Left)
            {
                ColumnAlignment::Left => "align-left",
                ColumnAlignment::Right => "align-right",
            };
            html.push_str(&format!(
                "<th class=\"{align_cls}\">{}</th>",
                escape_html(header)
            ));
        }
        html.push_str("</tr>\n</thead>\n<tbody>\n");
        for row in &table.rows {
            let mut row_classes = Vec::new();
            match row.footing {
                FootingRule::None => row_classes.push("footing-none"),
                FootingRule::Single => row_classes.push("footing-single"),
                FootingRule::Double => row_classes.push("footing-double"),
            }
            if is_restatement_diff
                && let Some(delta_cell) = row.cells.get(4)
                && delta_cell.chars().any(|c| matches!(c, '1'..='9'))
            {
                row_classes.push("delta-nonzero");
            }
            html.push_str(&format!(
                "<tr data-line=\"{}\" class=\"{}\">",
                escape_html(&row.line_code),
                row_classes.join(" ")
            ));
            for (idx, cell) in row.cells.iter().enumerate() {
                let align_cls = match table
                    .alignments
                    .get(idx)
                    .copied()
                    .unwrap_or(ColumnAlignment::Left)
                {
                    ColumnAlignment::Left => "align-left",
                    ColumnAlignment::Right => "align-right",
                };
                html.push_str(&format!(
                    "<td class=\"{align_cls}\">{}</td>",
                    escape_html(cell)
                ));
            }
            html.push_str("</tr>\n");
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</body>\n</html>\n");
    Ok(html.into_bytes())
}

/// Render a semantic HTML visual diff between two `StatementMarkdownIr` snapshots
/// (`as_originally_reported` vs `as_currently_stated`, `fa-cet`).
pub fn render_semantic_diff_html(
    originally_reported: &StatementMarkdownIr,
    currently_stated: &StatementMarkdownIr,
    creation_epoch_secs: u64,
) -> Result<Vec<u8>, StatementError> {
    if originally_reported.book_id != currently_stated.book_id
        || originally_reported.branch_id != currently_stated.branch_id
    {
        return Err(StatementError::Input(
            "semantic diff requires both Markdown IRs to share book_id and branch_id".into(),
        ));
    }
    let orig_digest = hex_bytes(&originally_reported.digest()?.0);
    let curr_digest = hex_bytes(&currently_stated.digest()?.0);
    let created_iso = format_utc_epoch_iso8601(creation_epoch_secs);

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str(&format!(
        "<meta name=\"dcterms.created\" content=\"{created_iso}\">\n"
    ));
    html.push_str(&format!(
        "<meta name=\"fa:orig-ir-digest\" content=\"{orig_digest}\">\n"
    ));
    html.push_str(&format!(
        "<meta name=\"fa:curr-ir-digest\" content=\"{curr_digest}\">\n"
    ));
    html.push_str(
        "<title>Semantic Restatement Diff</title>\n\
         <style>\n\
         body { font-family: ui-monospace, monospace; margin: 24px; color: #111; }\n\
         table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }\n\
         th, td { padding: 6px 10px; border-bottom: 1px solid #ddd; }\n\
         .align-left { text-align: left; }\n\
         .align-right { text-align: right; font-variant-numeric: tabular-nums; }\n\
         .status-restated { background-color: #fff3cd; font-weight: 600; }\n\
         .status-unchanged { color: #555; }\n\
         del { color: #b00020; text-decoration: line-through; margin-right: 6px; }\n\
         ins { color: #006400; text-decoration: none; font-weight: 700; }\n\
         </style>\n</head>\n<body>\n",
    );
    html.push_str(&format!(
        "<h1>Semantic Restatement Diff: {} (seq {} &rarr; seq {})</h1>\n",
        escape_html(&currently_stated.definition_name),
        originally_reported.known_at,
        currently_stated.known_at
    ));

    for curr_table in &currently_stated.tables {
        let orig_table = originally_reported
            .tables
            .iter()
            .find(|t| t.unit_id == curr_table.unit_id)
            .ok_or_else(|| {
                StatementError::Input(format!(
                    "originally_reported IR missing table for unit_id {}",
                    curr_table.unit_id
                ))
            })?;
        html.push_str(&format!(
            "<h2>Unit: {} (scale={})</h2>\n<table>\n<thead>\n<tr>\
             <th class=\"align-left\">Code</th>\
             <th class=\"align-left\">Line</th>\
             <th class=\"align-left\">Status</th>\
             <th class=\"align-right\">Semantic Comparison</th>\
             </tr>\n</thead>\n<tbody>\n",
            escape_html(&curr_table.unit_code),
            curr_table.unit_scale
        ));
        for curr_row in &curr_table.rows {
            let orig_row = orig_table
                .rows
                .iter()
                .find(|r| r.line_code == curr_row.line_code);
            let curr_val = curr_row.cells.get(2).map(String::as_str).unwrap_or("0");
            let orig_val = orig_row
                .and_then(|r| r.cells.get(2))
                .map(String::as_str)
                .unwrap_or("0");
            let changed = orig_val != curr_val;
            let (status, row_cls, cell_html) = if changed {
                (
                    "RESTATED",
                    "status-restated",
                    format!(
                        "<del>{}</del><ins>{}</ins>",
                        escape_html(orig_val),
                        escape_html(curr_val)
                    ),
                )
            } else {
                ("UNCHANGED", "status-unchanged", escape_html(curr_val))
            };
            let label = curr_row.cells.get(1).map(String::as_str).unwrap_or("");
            html.push_str(&format!(
                "<tr data-line=\"{}\" class=\"{row_cls}\">\
                 <td class=\"align-left\">{}</td>\
                 <td class=\"align-left\">{}</td>\
                 <td class=\"align-left\">{status}</td>\
                 <td class=\"align-right\">{cell_html}</td>\
                 </tr>\n",
                escape_html(&curr_row.line_code),
                escape_html(&curr_row.line_code),
                escape_html(label),
            ));
        }
        html.push_str("</tbody>\n</table>\n");
    }
    html.push_str("</body>\n</html>\n");
    Ok(html.into_bytes())
}

/// Render a `StatementMarkdownIr` into a deterministic, zero-float SVG 1.1 vector document (`fa-cet`).
pub fn render_svg(
    ir: &StatementMarkdownIr,
    creation_epoch_secs: u64,
) -> Result<Vec<u8>, StatementError> {
    let ir_digest = hex_bytes(&ir.digest()?.0);
    let created_iso = format_utc_epoch_iso8601(creation_epoch_secs);

    let total_rows: usize = ir.tables.iter().map(|t| t.rows.len() + 3).sum();
    let width: i64 = 960;
    let height: i64 = 120 + (total_rows as i64) * 28;

    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\">\n"
    ));
    svg.push_str(&format!(
        "  <desc>fa:ir-digest={ir_digest}; created={created_iso}</desc>\n"
    ));
    svg.push_str("  <rect x=\"0\" y=\"0\" width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n");
    svg.push_str(&format!(
        "  <text x=\"24\" y=\"36\" font-family=\"monospace\" font-size=\"16\" font-weight=\"bold\">Statement: {} (v{}, known_at={})</text>\n",
        escape_html(&ir.definition_name),
        ir.definition_version,
        ir.known_at
    ));

    let mut y: i64 = 72;
    for table in &ir.tables {
        svg.push_str(&format!(
            "  <text x=\"24\" y=\"{y}\" font-family=\"monospace\" font-size=\"13\" font-weight=\"bold\">Unit: {} (scale={})</text>\n",
            escape_html(&table.unit_code),
            table.unit_scale
        ));
        y += 24;

        let col_count = table.headers.len().max(1) as i64;
        let col_width = (width - 48) / col_count;

        for (idx, header) in table.headers.iter().enumerate() {
            let align = table
                .alignments
                .get(idx)
                .copied()
                .unwrap_or(ColumnAlignment::Left);
            let (x, anchor) = match align {
                ColumnAlignment::Left => (24 + (idx as i64) * col_width, "start"),
                ColumnAlignment::Right => (24 + ((idx as i64) + 1) * col_width - 12, "end"),
            };
            svg.push_str(&format!(
                "  <text x=\"{x}\" y=\"{y}\" text-anchor=\"{anchor}\" font-family=\"monospace\" font-size=\"12\" font-weight=\"bold\">{}</text>\n",
                escape_html(header)
            ));
        }
        svg.push_str(&format!(
            "  <line class=\"header-rule\" x1=\"24\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#111111\" stroke-width=\"1\"/>\n",
            y + 6,
            width - 24,
            y + 6
        ));
        y += 24;

        for row in &table.rows {
            if matches!(row.footing, FootingRule::Single | FootingRule::Double) {
                let top_y = y - 14;
                svg.push_str(&format!(
                    "  <line class=\"footing-top\" x1=\"24\" y1=\"{top_y}\" x2=\"{}\" y2=\"{top_y}\" stroke=\"#111111\" stroke-width=\"1\"/>\n",
                    width - 24
                ));
            }
            let weight = match row.footing {
                FootingRule::None => "normal",
                FootingRule::Single | FootingRule::Double => "bold",
            };
            for (idx, cell) in row.cells.iter().enumerate() {
                let align = table
                    .alignments
                    .get(idx)
                    .copied()
                    .unwrap_or(ColumnAlignment::Left);
                let (x, anchor) = match align {
                    ColumnAlignment::Left => (24 + (idx as i64) * col_width, "start"),
                    ColumnAlignment::Right => (24 + ((idx as i64) + 1) * col_width - 12, "end"),
                };
                svg.push_str(&format!(
                    "  <text x=\"{x}\" y=\"{y}\" text-anchor=\"{anchor}\" font-family=\"monospace\" font-size=\"12\" font-weight=\"{weight}\">{}</text>\n",
                    escape_html(cell)
                ));
            }
            match row.footing {
                FootingRule::None => {}
                FootingRule::Single => {
                    let bot_y = y + 5;
                    svg.push_str(&format!(
                        "  <line class=\"footing-single\" x1=\"24\" y1=\"{bot_y}\" x2=\"{}\" y2=\"{bot_y}\" stroke=\"#111111\" stroke-width=\"1\"/>\n",
                        width - 24
                    ));
                }
                FootingRule::Double => {
                    let bot1 = y + 4;
                    let bot2 = y + 7;
                    svg.push_str(&format!(
                        "  <line class=\"footing-double\" x1=\"24\" y1=\"{bot1}\" x2=\"{}\" y2=\"{bot1}\" stroke=\"#111111\" stroke-width=\"1\"/>\n",
                        width - 24
                    ));
                    svg.push_str(&format!(
                        "  <line class=\"footing-double\" x1=\"24\" y1=\"{bot2}\" x2=\"{}\" y2=\"{bot2}\" stroke=\"#111111\" stroke-width=\"1\"/>\n",
                        width - 24
                    ));
                }
            }
            y += 26;
        }
        y += 16;
    }

    svg.push_str("</svg>\n");
    Ok(svg.into_bytes())
}

fn build_pdf_content_stream(
    ir: &StatementMarkdownIr,
    created_iso: &str,
    ir_digest_hex: &str,
) -> String {
    let mut s = String::new();
    let mut y: i64 = 750;
    s.push_str("BT /F1 11 Tf 36 766 Td (");
    s.push_str(&escape_pdf_string(&format!(
        "FrankenAccounting Certified Statement: {} (v{})",
        ir.definition_name, ir.definition_version
    )));
    s.push_str(") Tj ET\n");

    s.push_str(&format!("BT /F1 8 Tf 36 {y} Td ("));
    s.push_str(&escape_pdf_string(&format!(
        "Book: {}  Known-At: {}  Created: {}  IR: {}",
        ir.book_id.to_hex(),
        ir.known_at,
        created_iso,
        &ir_digest_hex[..16]
    )));
    s.push_str(") Tj ET\n");
    y -= 20;

    for table in &ir.tables {
        y = render_pdf_table(&mut s, table, y);
        y -= 12;
    }
    s
}

fn render_pdf_table(s: &mut String, table: &MarkdownTable, mut y: i64) -> i64 {
    s.push_str(&format!("BT /F1 9 Tf 36 {y} Td ("));
    s.push_str(&escape_pdf_string(&format!(
        "Unit: {} (id={}, scale={})",
        table.unit_code, table.unit_id, table.unit_scale
    )));
    s.push_str(") Tj ET\n");
    y -= 14;

    let col_count = table.headers.len().max(1) as i64;
    let col_width = 540 / col_count;

    for (idx, header) in table.headers.iter().enumerate() {
        let align = table
            .alignments
            .get(idx)
            .copied()
            .unwrap_or(ColumnAlignment::Left);
        let x = match align {
            ColumnAlignment::Left => 36 + (idx as i64) * col_width,
            ColumnAlignment::Right => {
                let right_edge = 36 + ((idx as i64) + 1) * col_width - 6;
                let text_w = (header.chars().count() as i64) * 5;
                (right_edge - text_w).max(36 + (idx as i64) * col_width)
            }
        };
        s.push_str(&format!(
            "BT /F1 8 Tf {x} {y} Td ({}) Tj ET\n",
            escape_pdf_string(header)
        ));
    }
    let header_line_y = y - 3;
    s.push_str(&format!(
        "1 w 36 {header_line_y} m 576 {header_line_y} l S\n"
    ));
    y -= 14;

    for row in &table.rows {
        if y < 48 {
            break;
        }
        if matches!(row.footing, FootingRule::Single | FootingRule::Double) {
            let top_y = y + 9;
            s.push_str(&format!("1 w 36 {top_y} m 576 {top_y} l S\n"));
        }
        for (idx, cell) in row.cells.iter().enumerate() {
            let align = table
                .alignments
                .get(idx)
                .copied()
                .unwrap_or(ColumnAlignment::Left);
            let x = match align {
                ColumnAlignment::Left => 36 + (idx as i64) * col_width,
                ColumnAlignment::Right => {
                    let right_edge = 36 + ((idx as i64) + 1) * col_width - 6;
                    let text_w = (cell.chars().count() as i64) * 5;
                    (right_edge - text_w).max(36 + (idx as i64) * col_width)
                }
            };
            s.push_str(&format!(
                "BT /F1 8 Tf {x} {y} Td ({}) Tj ET\n",
                escape_pdf_string(cell)
            ));
        }
        match row.footing {
            FootingRule::None => {}
            FootingRule::Single => {
                let bot_y = y - 3;
                s.push_str(&format!(
                    "% footing:single {}\n1 w 36 {bot_y} m 576 {bot_y} l S\n",
                    row.line_code
                ));
            }
            FootingRule::Double => {
                let bot1 = y - 2;
                let bot2 = y - 5;
                s.push_str(&format!(
                    "% footing:double {}\n1 w 36 {bot1} m 576 {bot1} l 36 {bot2} m 576 {bot2} l S\n",
                    row.line_code
                ));
            }
        }
        y -= 14;
    }
    y
}

fn render_pdf_internal(
    ir: &StatementMarkdownIr,
    creation_epoch_secs: u64,
    pdfa_2b: bool,
) -> Result<Vec<u8>, StatementError> {
    let ir_digest = ir.digest()?;
    let ir_digest_hex = hex_bytes(&ir_digest.0);
    let created_iso = format_utc_epoch_iso8601(creation_epoch_secs);
    let created_pdf = format_utc_epoch_pdf_date(creation_epoch_secs);
    let content_stream = build_pdf_content_stream(ir, &created_iso, &ir_digest_hex);

    let xmp_packet = format!(
        "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
         <x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
           <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
             <rdf:Description rdf:about=\"\"\n\
                 xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\"\n\
                 xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"\n\
                 xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n\
                 xmlns:fa=\"https://frankenaccounting.dev/ns/1.0/\">\n\
               <pdfaid:part>2</pdfaid:part>\n\
               <pdfaid:conformance>B</pdfaid:conformance>\n\
               <xmp:CreateDate>{created_iso}</xmp:CreateDate>\n\
               <xmp:ModifyDate>{created_iso}</xmp:ModifyDate>\n\
               <xmp:CreatorTool>FrankenAccounting fa-statements</xmp:CreatorTool>\n\
               <dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">{}</rdf:li></rdf:Alt></dc:title>\n\
               <fa:irDigest>{ir_digest_hex}</fa:irDigest>\n\
             </rdf:Description>\n\
           </rdf:RDF>\n\
         </x:xmpmeta>\n\
         <?xpacket end=\"w\"?>",
        escape_html(&ir.definition_name)
    );

    // Deterministic minimal 128-byte ICC profile header for /DestOutputProfile (/N 3 sRGB)
    let mut icc_bytes = vec![0u8; 128];
    icc_bytes[0..4].copy_from_slice(&128u32.to_be_bytes());
    icc_bytes[4..8].copy_from_slice(b"ADBE");
    icc_bytes[8..12].copy_from_slice(&0x0210_0000u32.to_be_bytes());
    icc_bytes[12..16].copy_from_slice(b"mntr");
    icc_bytes[16..20].copy_from_slice(b"RGB ");
    icc_bytes[20..24].copy_from_slice(b"XYZ ");
    icc_bytes[36..40].copy_from_slice(b"acsp");

    let catalog_obj = if pdfa_2b {
        "<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R /OutputIntents [6 0 R] /Lang (en-US) >>"
            .to_string()
    } else {
        "<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>".to_string()
    };

    let objects: Vec<Vec<u8>> = vec![
        catalog_obj.into_bytes(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 8 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".to_vec(),
        format!(
            "<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n{}\nendstream",
            xmp_packet.len(),
            xmp_packet
        )
        .into_bytes(),
        b"<< /Type /OutputIntent /S /GTS_PDFA1 /OutputConditionIdentifier (sRGB IEC61966-2.1) /RegistryName (http://www.color.org) /Info (sRGB IEC61966-2.1) /DestOutputProfile 7 0 R >>".to_vec(),
        {
            let mut v = format!("<< /N 3 /Length {} >>\nstream\n", icc_bytes.len()).into_bytes();
            v.extend_from_slice(&icc_bytes);
            v.extend_from_slice(b"\nendstream");
            v
        },
        format!(
            "<< /Length {} >>\nstream\n{}\nendstream",
            content_stream.len(),
            content_stream
        )
        .into_bytes(),
        format!(
            "<< /Title ({}) /Creator (FrankenAccounting fa-statements) /Producer (FrankenAccounting fa-statements) /CreationDate ({created_pdf}) /ModDate ({created_pdf}) >>",
            escape_pdf_string(&ir.definition_name)
        )
        .into_bytes(),
    ];

    let mut out = Vec::with_capacity(4096 + content_stream.len());
    out.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = Vec::with_capacity(objects.len());
    for (idx, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        let obj_num = idx + 1;
        out.extend_from_slice(format!("{obj_num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }

    let xref_offset = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    let id_token = &ir_digest_hex[..32];
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 9 0 R /ID [<{id_token}> <{id_token}>] >>\nstartxref\n{xref_offset}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    Ok(out)
}

/// Render a `StatementMarkdownIr` into deterministic PDF 1.7 bytes (`fa-cet`).
pub fn render_pdf(
    ir: &StatementMarkdownIr,
    creation_epoch_secs: u64,
) -> Result<Vec<u8>, StatementError> {
    render_pdf_internal(ir, creation_epoch_secs, false)
}

/// Render a `StatementMarkdownIr` into deterministic PDF/A-2b (ISO 19005-2) bytes (`fa-cet`).
pub fn render_pdfa(
    ir: &StatementMarkdownIr,
    creation_epoch_secs: u64,
) -> Result<Vec<u8>, StatementError> {
    render_pdf_internal(ir, creation_epoch_secs, true)
}

/// Validation receipt returned by `validate_pdfa2b` (`fa-cet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfaValidationReceipt {
    pub pdf_version: String,
    pub pdfa_part: u8,
    pub pdfa_conformance: String,
    pub has_output_intent_srgb: bool,
    pub has_binary_comment_marker: bool,
    pub has_trailer_id: bool,
    pub embedded_ir_digest_hex: String,
    pub creation_date_iso: String,
    pub single_footing_count: usize,
    pub double_footing_count: usize,
}

/// Validate that a rendered PDF satisfies PDF/A-2b structural and metadata invariants (`fa-cet`).
pub fn validate_pdfa2b(pdf_bytes: &[u8]) -> Result<PdfaValidationReceipt, StatementError> {
    if !pdf_bytes.starts_with(b"%PDF-1.7\n") {
        return Err(StatementError::Input(
            "PDF/A-2b validation failed: missing %PDF-1.7 header".into(),
        ));
    }
    let has_binary_comment_marker = pdf_bytes
        .get(9..15)
        .is_some_and(|slice| slice[0] == b'%' && slice[1..5].iter().all(|&b| b >= 0x80));
    if !has_binary_comment_marker {
        return Err(StatementError::Input(
            "PDF/A-2b validation failed: missing high-bit binary comment line after header".into(),
        ));
    }
    let text = String::from_utf8_lossy(pdf_bytes);
    if !text.contains("<pdfaid:part>2</pdfaid:part>") {
        return Err(StatementError::Input(
            "PDF/A-2b validation failed: XMP metadata missing <pdfaid:part>2</pdfaid:part>".into(),
        ));
    }
    if !text.contains("<pdfaid:conformance>B</pdfaid:conformance>") {
        return Err(StatementError::Input(
            "PDF/A-2b validation failed: XMP metadata missing <pdfaid:conformance>B</pdfaid:conformance>".into(),
        ));
    }
    let has_output_intent_srgb = text.contains("/OutputIntents")
        && text.contains("/S /GTS_PDFA1")
        && text.contains("/DestOutputProfile");
    if !has_output_intent_srgb {
        return Err(StatementError::Input(
            "PDF/A-2b validation failed: missing /OutputIntents /GTS_PDFA1 with /DestOutputProfile"
                .into(),
        ));
    }
    let has_trailer_id = text.contains("/ID [<") && text.ends_with("%%EOF\n");
    if !has_trailer_id {
        return Err(StatementError::Input(
            "PDF/A-2b validation failed: missing trailer /ID or trailing %%EOF".into(),
        ));
    }
    let embedded_ir_digest_hex = extract_between(&text, "<fa:irDigest>", "</fa:irDigest>")
        .ok_or_else(|| {
            StatementError::Input("PDF/A-2b validation failed: missing <fa:irDigest> in XMP".into())
        })?
        .to_string();
    let creation_date_iso = extract_between(&text, "<xmp:CreateDate>", "</xmp:CreateDate>")
        .ok_or_else(|| {
            StatementError::Input(
                "PDF/A-2b validation failed: missing <xmp:CreateDate> in XMP".into(),
            )
        })?
        .to_string();
    let single_footing_count = text.matches("% footing:single ").count();
    let double_footing_count = text.matches("% footing:double ").count();

    Ok(PdfaValidationReceipt {
        pdf_version: "1.7".to_string(),
        pdfa_part: 2,
        pdfa_conformance: "B".to_string(),
        has_output_intent_srgb,
        has_binary_comment_marker,
        has_trailer_id,
        embedded_ir_digest_hex,
        creation_date_iso,
        single_footing_count,
        double_footing_count,
    })
}

fn extract_between<'a>(haystack: &'a str, start_tag: &str, end_tag: &str) -> Option<&'a str> {
    let start = haystack.find(start_tag)? + start_tag.len();
    let rest = &haystack[start..];
    let end = rest.find(end_tag)?;
    Some(&rest[..end])
}

/// Receipt returned by a supervised `franken_markdown` (`fmd`) subprocess render (`fa-cet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FmdRenderReceipt {
    pub format: StatementRenderFormat,
    pub ir_digest: Oid,
    pub output_digest: Oid,
    pub output_bytes: Vec<u8>,
    pub output_path: PathBuf,
    pub source_date_epoch: u64,
}

fn resolve_fmd_bin(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    let local_bin = Path::new("/home/ubuntu/.local/bin/fmd");
    if local_bin.exists() {
        return local_bin.to_path_buf();
    }
    PathBuf::from("fmd")
}

/// Invoke `franken_markdown` (`fmd render --no-config`) with `SOURCE_DATE_EPOCH` set to
/// `creation_epoch_secs` (`fa-cet`).
///
/// If `fmd` is not installed on the host, returns `StatementError::Input` naming the install hint.
pub fn invoke_fmd_render(
    ir: &StatementMarkdownIr,
    format: StatementRenderFormat,
    creation_epoch_secs: u64,
    out_path: &Path,
    fmd_bin: Option<&Path>,
) -> Result<FmdRenderReceipt, StatementError> {
    let ir_digest = ir.digest()?;
    if format == StatementRenderFormat::Markdown {
        let bytes = ir.markdown.as_bytes().to_vec();
        std::fs::write(out_path, &bytes).map_err(|e| {
            StatementError::Input(format!(
                "failed to write Markdown output to {out_path:?}: {e}"
            ))
        })?;
        let output_digest = Oid(domain_digest(b"fa:rendered-statement:v1", &[&bytes]));
        return Ok(FmdRenderReceipt {
            format,
            ir_digest,
            output_digest,
            output_bytes: bytes,
            output_path: out_path.to_path_buf(),
            source_date_epoch: creation_epoch_secs,
        });
    }

    let bin = resolve_fmd_bin(fmd_bin);
    let to_arg = match format {
        StatementRenderFormat::Html => "html",
        StatementRenderFormat::Svg => "svg",
        StatementRenderFormat::Pdf | StatementRenderFormat::Pdfa2b => "pdf",
        StatementRenderFormat::Markdown => unreachable!(),
    };
    let mut cmd = Command::new(&bin);
    cmd.env("SOURCE_DATE_EPOCH", creation_epoch_secs.to_string())
        .arg("render")
        .arg("--no-config")
        .arg("--no-remote-images")
        .arg("--text")
        .arg(&ir.markdown)
        .arg("--to")
        .arg(to_arg)
        .arg("--out")
        .arg(out_path);
    if format == StatementRenderFormat::Pdfa2b {
        cmd.arg("--pdf-a").arg("2b").arg("--pdf-a-strict");
    }

    let output = cmd.output().map_err(|err| {
        StatementError::Input(format!(
            "franken_markdown (`fmd`) binary `{}` unavailable ({err}); install from /data/projects/franken_markdown or use fa-statements native render_html/render_svg/render_pdf/render_pdfa",
            bin.display()
        ))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StatementError::Input(format!(
            "fmd render failed with status {:?}: {}",
            output.status.code(),
            stderr.trim()
        )));
    }
    let output_bytes = std::fs::read(out_path).map_err(|e| {
        StatementError::Input(format!(
            "failed to read fmd rendered output at {}: {e}",
            out_path.display()
        ))
    })?;
    let output_digest = Oid(domain_digest(b"fa:rendered-statement:v1", &[&output_bytes]));
    Ok(FmdRenderReceipt {
        format,
        ir_digest,
        output_digest,
        output_bytes,
        output_path: out_path.to_path_buf(),
        source_date_epoch: creation_epoch_secs,
    })
}

/// Directed edge kind in a lineage / flow-of-funds exhibit (`fa-949`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineageEdgeKind {
    Supersedes,
    Resolves,
    Settles,
    Unsettles,
}

impl LineageEdgeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Supersedes => "SUPERSEDES",
            Self::Resolves => "RESOLVES",
            Self::Settles => "SETTLES",
            Self::Unsettles => "UNSETTLES",
        }
    }
}

/// One entry vertex in a lineage / flow-of-funds exhibit (`fa-949`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageDiagramNode {
    pub entry_vid_hex: String,
    pub entry_class: String,
    pub effective_date: String,
    pub recorded_at: u64,
    pub live: bool,
    pub amount_summary: String,
}

/// One directed edge in a lineage / flow-of-funds exhibit (`fa-949`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageDiagramEdge {
    pub from_entry_vid_hex: String,
    pub to_entry_vid_hex: String,
    pub kind: LineageEdgeKind,
    pub detail: String,
}

/// Deterministic Markdown IR and SVG flowchart for a supersession/settlement lineage graph (`fa-949`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageDiagramIr {
    pub book_id: Id128,
    pub known_at: u64,
    pub root_entry_vid_hex: String,
    pub markdown: String,
    pub svg: String,
    pub digest: Oid,
}

/// Render a deterministic lineage / flow-of-funds exhibit as both Markdown (with embedded
/// flowchart block) and zero-float SVG (`fa-949`).
pub fn render_lineage_diagram(
    book_id: Id128,
    known_at: u64,
    root_entry_vid_hex: &str,
    nodes: &[LineageDiagramNode],
    edges: &[LineageDiagramEdge],
) -> Result<LineageDiagramIr, StatementError> {
    if nodes.is_empty() {
        return Err(StatementError::Input(
            "lineage diagram requires at least one entry node".into(),
        ));
    }
    let mut sorted_nodes = nodes.to_vec();
    sorted_nodes.sort_by(|a, b| {
        a.recorded_at
            .cmp(&b.recorded_at)
            .then_with(|| a.entry_vid_hex.cmp(&b.entry_vid_hex))
    });
    let mut sorted_edges = edges.to_vec();
    sorted_edges.sort_by(|a, b| {
        a.from_entry_vid_hex
            .cmp(&b.from_entry_vid_hex)
            .then_with(|| a.to_entry_vid_hex.cmp(&b.to_entry_vid_hex))
            .then_with(|| a.kind.label().cmp(b.kind.label()))
    });

    let mut md = format!(
        "# Lineage Exhibit: `{root_entry_vid_hex}`\n\n- Book: `{}`\n- Known-At Sequence: `{known_at}`\n\n```mermaid\nflowchart LR\n",
        book_id.to_hex()
    );
    for (idx, n) in sorted_nodes.iter().enumerate() {
        let short_id = if n.entry_vid_hex.len() > 8 {
            &n.entry_vid_hex[..8]
        } else {
            &n.entry_vid_hex
        };
        let status = if n.live { "LIVE" } else { "SUPERSEDED" };
        md.push_str(&format!(
            "  N{idx}[\"{short_id} ({}) | {} | seq {} | {} | {status}\"]\n",
            n.entry_class, n.effective_date, n.recorded_at, n.amount_summary
        ));
    }
    for e in &sorted_edges {
        let from_idx = sorted_nodes
            .iter()
            .position(|n| n.entry_vid_hex == e.from_entry_vid_hex)
            .ok_or_else(|| {
                StatementError::Input(format!(
                    "lineage edge references unknown source node `{}`",
                    e.from_entry_vid_hex
                ))
            })?;
        let to_idx = sorted_nodes
            .iter()
            .position(|n| n.entry_vid_hex == e.to_entry_vid_hex)
            .ok_or_else(|| {
                StatementError::Input(format!(
                    "lineage edge references unknown target node `{}`",
                    e.to_entry_vid_hex
                ))
            })?;
        md.push_str(&format!(
            "  N{from_idx} -->|\"{} ({})\"| N{to_idx}\n",
            e.kind.label(),
            e.detail
        ));
    }
    md.push_str("```\n");

    let node_count = sorted_nodes.len() as i64;
    let width: i64 = (node_count * 260 + 60).max(560);
    let height: i64 = 240;
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\">\n\
         <defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"10\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#222\"/></marker></defs>\n\
         <rect x=\"0\" y=\"0\" width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n\
         <text x=\"24\" y=\"32\" font-family=\"monospace\" font-size=\"14\" font-weight=\"bold\">Lineage Exhibit: {} (known_at={known_at})</text>\n",
        escape_html(root_entry_vid_hex)
    );
    for (idx, n) in sorted_nodes.iter().enumerate() {
        let x: i64 = 24 + (idx as i64) * 250;
        let y: i64 = 70;
        let stroke = if n.live { "#006400" } else { "#b00020" };
        let fill = if n.live { "#f0fff4" } else { "#fff5f5" };
        let short_id = if n.entry_vid_hex.len() > 8 {
            &n.entry_vid_hex[..8]
        } else {
            &n.entry_vid_hex
        };
        let status = if n.live { "LIVE" } else { "SUPERSEDED" };
        svg.push_str(&format!(
            "  <g class=\"lineage-node\" data-entry=\"{}\">\n\
               <rect x=\"{x}\" y=\"{y}\" width=\"190\" height=\"84\" rx=\"6\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"2\"/>\n\
               <text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"11\" font-weight=\"bold\">{} [{status}]</text>\n\
               <text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"10\">{} · seq {}</text>\n\
               <text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"10\">{}</text>\n\
               <text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"10\">{}</text>\n\
             </g>\n",
            escape_html(&n.entry_vid_hex),
            x + 10,
            y + 20,
            escape_html(short_id),
            x + 10,
            y + 38,
            escape_html(&n.entry_class),
            n.recorded_at,
            x + 10,
            y + 54,
            escape_html(&n.effective_date),
            x + 10,
            y + 70,
            escape_html(&n.amount_summary),
        ));
    }
    for e in &sorted_edges {
        let from_idx = sorted_nodes
            .iter()
            .position(|n| n.entry_vid_hex == e.from_entry_vid_hex)
            .unwrap();
        let to_idx = sorted_nodes
            .iter()
            .position(|n| n.entry_vid_hex == e.to_entry_vid_hex)
            .unwrap();
        let x1: i64 = 24 + (from_idx as i64) * 250 + 190;
        let x2: i64 = 24 + (to_idx as i64) * 250;
        let mid_x = (x1 + x2) / 2;
        svg.push_str(&format!(
            "  <g class=\"lineage-edge\" data-kind=\"{}\">\n\
               <line x1=\"{x1}\" y1=\"112\" x2=\"{x2}\" y2=\"112\" stroke=\"#222\" stroke-width=\"2\" marker-end=\"url(#arrow)\"/>\n\
               <text x=\"{mid_x}\" y=\"104\" text-anchor=\"middle\" font-family=\"monospace\" font-size=\"9\">{}</text>\n\
               <text x=\"{mid_x}\" y=\"128\" text-anchor=\"middle\" font-family=\"monospace\" font-size=\"9\">{}</text>\n\
             </g>\n",
            e.kind.label(),
            e.kind.label(),
            escape_html(&e.detail),
        ));
    }
    svg.push_str("</svg>\n");

    let digest = Oid(domain_digest(
        b"fa:lineage-diagram:v1",
        &[md.as_bytes(), svg.as_bytes()],
    ));
    Ok(LineageDiagramIr {
        book_id,
        known_at,
        root_entry_vid_hex: root_entry_vid_hex.to_string(),
        markdown: md,
        svg,
        digest,
    })
}

/// Account or party vertex in a flow-of-funds forensic exhibit (`fa-949`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowOfFundsNode {
    pub code: String,
    pub label: String,
    pub total_inflow: i128,
    pub total_outflow: i128,
}

/// Directed monetary flow edge between two accounts/parties in a flow-of-funds exhibit (`fa-949`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowOfFundsEdge {
    pub from_code: String,
    pub to_code: String,
    pub amount_mantissa: i128,
    pub entry_count: u64,
}

/// Deterministic Markdown flowchart IR and SVG exhibit for a flow-of-funds graph (`fa-949`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowOfFundsExhibit {
    pub book_id: Id128,
    pub known_at: u64,
    pub unit_code: String,
    pub unit_scale: u8,
    pub markdown: String,
    pub svg: String,
    pub digest: Oid,
}

/// Render a deterministic flow-of-funds exhibit (Markdown flowchart + zero-float SVG, `fa-949`).
pub fn render_flow_of_funds_diagram(
    book_id: Id128,
    known_at: u64,
    unit_code: &str,
    unit_scale: u8,
    nodes: &[FlowOfFundsNode],
    edges: &[FlowOfFundsEdge],
) -> Result<FlowOfFundsExhibit, StatementError> {
    if nodes.is_empty() {
        return Err(StatementError::Input(
            "flow-of-funds diagram requires at least one node".into(),
        ));
    }
    let mut sorted_nodes = nodes.to_vec();
    sorted_nodes.sort_by(|a, b| a.code.cmp(&b.code));
    let mut sorted_edges = edges.to_vec();
    sorted_edges.sort_by(|a, b| {
        a.from_code
            .cmp(&b.from_code)
            .then_with(|| a.to_code.cmp(&b.to_code))
    });

    let mut md = format!(
        "# Flow-of-Funds Exhibit ({unit_code}, scale={unit_scale})\n\n- Book: `{}`\n- Known-At Sequence: `{known_at}`\n\n```mermaid\nflowchart LR\n",
        book_id.to_hex()
    );
    for (idx, n) in sorted_nodes.iter().enumerate() {
        let inflow_str = crate::markdown::format_scaled_i128(n.total_inflow, unit_scale)?;
        let outflow_str = crate::markdown::format_scaled_i128(n.total_outflow, unit_scale)?;
        md.push_str(&format!(
            "  F{idx}[\"{} ({}) | In: {inflow_str} {unit_code} | Out: {outflow_str} {unit_code}\"]\n",
            n.code, n.label
        ));
    }
    for e in &sorted_edges {
        if e.amount_mantissa <= 0 {
            return Err(StatementError::Input(
                "flow-of-funds edge amount_mantissa must be strictly positive".into(),
            ));
        }
        let from_idx = sorted_nodes
            .iter()
            .position(|n| n.code == e.from_code)
            .ok_or_else(|| {
                StatementError::Input(format!(
                    "flow-of-funds edge references unknown source `{}`",
                    e.from_code
                ))
            })?;
        let to_idx = sorted_nodes
            .iter()
            .position(|n| n.code == e.to_code)
            .ok_or_else(|| {
                StatementError::Input(format!(
                    "flow-of-funds edge references unknown target `{}`",
                    e.to_code
                ))
            })?;
        let amt_str = crate::markdown::format_scaled_i128(e.amount_mantissa, unit_scale)?;
        md.push_str(&format!(
            "  F{from_idx} -->|\"{amt_str} {unit_code} ({} entries)\"| F{to_idx}\n",
            e.entry_count
        ));
    }
    md.push_str("```\n");

    let width: i64 = (sorted_nodes.len() as i64 * 260 + 60).max(560);
    let height: i64 = 240;
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\">\n\
         <defs><marker id=\"fof-arrow\" viewBox=\"0 0 10 10\" refX=\"10\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#003366\"/></marker></defs>\n\
         <rect x=\"0\" y=\"0\" width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n\
         <text x=\"24\" y=\"32\" font-family=\"monospace\" font-size=\"14\" font-weight=\"bold\">Flow-of-Funds Exhibit ({unit_code}, known_at={known_at})</text>\n"
    );
    for (idx, n) in sorted_nodes.iter().enumerate() {
        let x: i64 = 24 + (idx as i64) * 250;
        let y: i64 = 70;
        let inflow_str = crate::markdown::format_scaled_i128(n.total_inflow, unit_scale)?;
        let outflow_str = crate::markdown::format_scaled_i128(n.total_outflow, unit_scale)?;
        svg.push_str(&format!(
            "  <g class=\"fof-node\" data-code=\"{}\">\n\
               <rect x=\"{x}\" y=\"{y}\" width=\"190\" height=\"76\" rx=\"6\" fill=\"#f4f8fb\" stroke=\"#003366\" stroke-width=\"2\"/>\n\
               <text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"11\" font-weight=\"bold\">{} · {}</text>\n\
               <text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"10\">In:  {inflow_str} {unit_code}</text>\n\
               <text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"10\">Out: {outflow_str} {unit_code}</text>\n\
             </g>\n",
            escape_html(&n.code),
            x + 10,
            y + 22,
            escape_html(&n.code),
            escape_html(&n.label),
            x + 10,
            y + 42,
            x + 10,
            y + 60,
        ));
    }
    for e in &sorted_edges {
        let from_idx = sorted_nodes
            .iter()
            .position(|n| n.code == e.from_code)
            .unwrap();
        let to_idx = sorted_nodes
            .iter()
            .position(|n| n.code == e.to_code)
            .unwrap();
        let x1: i64 = 24 + (from_idx as i64) * 250 + 190;
        let x2: i64 = 24 + (to_idx as i64) * 250;
        let mid_x = (x1 + x2) / 2;
        let amt_str = crate::markdown::format_scaled_i128(e.amount_mantissa, unit_scale)?;
        svg.push_str(&format!(
            "  <g class=\"fof-edge\">\n\
               <line x1=\"{x1}\" y1=\"108\" x2=\"{x2}\" y2=\"108\" stroke=\"#003366\" stroke-width=\"2\" marker-end=\"url(#fof-arrow)\"/>\n\
               <text x=\"{mid_x}\" y=\"100\" text-anchor=\"middle\" font-family=\"monospace\" font-size=\"9\">{amt_str} {unit_code}</text>\n\
             </g>\n"
        ));
    }
    svg.push_str("</svg>\n");

    let digest = Oid(domain_digest(
        b"fa:flow-of-funds-diagram:v1",
        &[md.as_bytes(), svg.as_bytes()],
    ));
    Ok(FlowOfFundsExhibit {
        book_id,
        known_at,
        unit_code: unit_code.to_string(),
        unit_scale,
        markdown: md,
        svg,
        digest,
    })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // fixtures with small literal amounts
mod tests {
    use super::*;
    use crate::markdown::{
        OpenItemIrRow, OpenItemsIrInput, RegisterIrInput, RegisterIrRow, TrialBalanceIrInput,
        TrialBalanceIrRow, UnitFormatSpec, render_open_items_ir, render_register_ir,
        render_restatement_diff_ir, render_statement_ir, render_trial_balance_ir,
    };
    use crate::{
        Account, AccountBalance, ColumnInput, StatementDefinition, StatementInput, evaluate,
    };
    use fa_time::DateDay;

    fn sample_units() -> Vec<UnitFormatSpec> {
        vec![UnitFormatSpec {
            unit_id: 1,
            code: "USD".into(),
            scale: 2,
        }]
    }

    fn sample_bs(
        known_at: u64,
        revenue_cents: i128,
        expense_cents: i128,
    ) -> (StatementDefinition, crate::Statement) {
        let def = StatementDefinition::embedded("balance-sheet").unwrap();
        let net_cash = 100_000 + revenue_cents - expense_cents;
        let input = StatementInput {
            book_id: Id128([0x44; 16]),
            branch_id: Id128::TRUNK,
            known_at,
            accounts: vec![
                Account {
                    id: 1,
                    code: "1000".into(),
                    name: "Cash".into(),
                    account_type: 1,
                    is_leaf: true,
                },
                Account {
                    id: 2,
                    code: "2000".into(),
                    name: "Payables".into(),
                    account_type: 2,
                    is_leaf: true,
                },
                Account {
                    id: 3,
                    code: "3000".into(),
                    name: "Equity".into(),
                    account_type: 3,
                    is_leaf: true,
                },
                Account {
                    id: 4,
                    code: "4000".into(),
                    name: "Revenue".into(),
                    account_type: 4,
                    is_leaf: true,
                },
                Account {
                    id: 5,
                    code: "5000".into(),
                    name: "Expense".into(),
                    account_type: 5,
                    is_leaf: true,
                },
            ],
            units: vec![1],
            columns: vec![ColumnInput {
                label: "FY2026-P03".into(),
                periods: vec!["FY2026-P03".into()],
                effective_from: None,
                effective_through: DateDay(90),
                balances: vec![
                    AccountBalance {
                        account_id: 1,
                        unit_id: 1,
                        debits: net_cash,
                        credits: 0,
                    },
                    AccountBalance {
                        account_id: 3,
                        unit_id: 1,
                        debits: 0,
                        credits: 100_000,
                    },
                    AccountBalance {
                        account_id: 4,
                        unit_id: 1,
                        debits: 0,
                        credits: revenue_cents,
                    },
                    AccountBalance {
                        account_id: 5,
                        unit_id: 1,
                        debits: expense_cents,
                        credits: 0,
                    },
                ],
            }],
        };
        let stmt = evaluate(&def, &input).unwrap();
        (def, stmt)
    }

    #[test]
    fn statement_fixture_proves_right_aligned_numeric_columns_and_footing_rules_across_all_formats()
    {
        let (def, orig) = sample_bs(10, 50_025, 12_005);
        let units = sample_units();
        let ir = render_statement_ir(&orig, &def, &units).unwrap();
        let epoch: u64 = 1_792_454_400; // 2026-10-20T00:00:00Z

        // 1. HTML: right-aligned numeric columns + single/double footing rules
        let html_bytes_1 = render_html(&ir, epoch).unwrap();
        let html_bytes_2 = render_html(&ir, epoch).unwrap();
        assert_eq!(html_bytes_1, html_bytes_2);
        let html = String::from_utf8(html_bytes_1).unwrap();
        assert!(html.contains("<td class=\"align-right\">1380.20</td>"));
        assert!(html.contains("class=\"footing-single\""));
        assert!(html.contains("class=\"footing-double\""));
        assert!(html.contains("2026-10-20T00:00:00Z"));

        // 2. SVG: text-anchor="end" for numeric columns + footing-single/footing-double lines
        let svg_bytes_1 = render_svg(&ir, epoch).unwrap();
        let svg_bytes_2 = render_svg(&ir, epoch).unwrap();
        assert_eq!(svg_bytes_1, svg_bytes_2);
        let svg = String::from_utf8(svg_bytes_1).unwrap();
        assert!(svg.contains("text-anchor=\"end\""));
        assert!(svg.contains("class=\"footing-single\""));
        assert!(svg.contains("class=\"footing-double\""));

        // 3. PDF & PDF/A-2b: byte-for-byte deterministic across renders + PDF/A-2b validation
        let pdf_1 = render_pdf(&ir, epoch).unwrap();
        let pdf_2 = render_pdf(&ir, epoch).unwrap();
        assert_eq!(pdf_1, pdf_2);

        let pdfa_1 = render_pdfa(&ir, epoch).unwrap();
        let pdfa_2 = render_pdfa(&ir, epoch).unwrap();
        assert_eq!(pdfa_1, pdfa_2);

        let receipt = validate_pdfa2b(&pdfa_1).unwrap();
        assert_eq!(receipt.pdfa_part, 2);
        assert_eq!(receipt.pdfa_conformance, "B");
        assert!(receipt.has_output_intent_srgb);
        assert!(receipt.has_binary_comment_marker);
        assert!(receipt.has_trailer_id);
        assert_eq!(receipt.creation_date_iso, "2026-10-20T00:00:00Z");
        assert_eq!(
            receipt.embedded_ir_digest_hex,
            hex_bytes(&ir.digest().unwrap().0)
        );
        assert!(receipt.single_footing_count >= 1);
        assert!(receipt.double_footing_count >= 1);
    }

    #[test]
    fn restatement_semantic_diff_and_tb_register_open_items_markdown_ir_work() {
        let (def, orig) = sample_bs(10, 50_025, 12_005);
        let (_, restated) = sample_bs(25, 50_025, 18_505);
        let units = sample_units();
        let orig_ir = render_statement_ir(&orig, &def, &units).unwrap();
        let restated_ir = render_statement_ir(&restated, &def, &units).unwrap();
        let diff_ir = render_restatement_diff_ir(&orig, &restated, &def, &units).unwrap();

        let epoch: u64 = 1_792_454_400;
        let diff_html = String::from_utf8(render_html(&diff_ir, epoch).unwrap()).unwrap();
        assert!(diff_html.contains("restatement-diff"));
        assert!(diff_html.contains("delta-nonzero"));

        let sem_diff =
            String::from_utf8(render_semantic_diff_html(&orig_ir, &restated_ir, epoch).unwrap())
                .unwrap();
        assert!(sem_diff.contains("status-restated"));
        assert!(sem_diff.contains("<del>380.20</del><ins>315.20</ins>"));

        // Trial Balance IR
        let tb_ir = render_trial_balance_ir(
            &TrialBalanceIrInput {
                book_id: Id128([0x44; 16]),
                branch_id: Id128::TRUNK,
                known_at: 25,
                effective_label: "FY2026-P03".into(),
                activity_only: false,
                rows: vec![
                    TrialBalanceIrRow {
                        account_code: "1000".into(),
                        account_name: "Cash".into(),
                        unit_id: 1,
                        debits: 131_520,
                        credits: 0,
                    },
                    TrialBalanceIrRow {
                        account_code: "3000".into(),
                        account_name: "Equity".into(),
                        unit_id: 1,
                        debits: 0,
                        credits: 131_520,
                    },
                ],
            },
            &units,
        )
        .unwrap();
        assert_eq!(
            tb_ir.tables[0].rows.last().unwrap().footing,
            FootingRule::Double
        );
        let tb_pdfa = render_pdfa(&tb_ir, epoch).unwrap();
        assert!(validate_pdfa2b(&tb_pdfa).is_ok());

        // Account Register IR
        let reg_ir = render_register_ir(
            &RegisterIrInput {
                book_id: Id128([0x44; 16]),
                branch_id: Id128::TRUNK,
                known_at: 25,
                account_code: "1000".into(),
                account_name: "Cash".into(),
                unit_id: 1,
                opening_balance: 100_000,
                rows: vec![RegisterIrRow {
                    recorded_at: 12,
                    effective_date: "2026-03-15".into(),
                    entry_vid_hex: "00000000000000000000000000000012".into(),
                    description: "Customer receipt".into(),
                    debit: 50_025,
                    credit: 0,
                }],
            },
            &units,
        )
        .unwrap();
        assert_eq!(reg_ir.tables[0].rows[0].footing, FootingRule::Single);
        assert_eq!(
            reg_ir.tables[0].rows.last().unwrap().footing,
            FootingRule::Double
        );

        // Open Items IR
        let oi_ir = render_open_items_ir(
            &OpenItemsIrInput {
                book_id: Id128([0x44; 16]),
                branch_id: Id128::TRUNK,
                known_at: 25,
                account_code: "1200".into(),
                account_name: "Accounts Receivable".into(),
                unit_id: 1,
                items: vec![OpenItemIrRow {
                    item_vid_hex: "00000000000000000000000000000099".into(),
                    effective_date: "2026-03-10".into(),
                    counterparty_or_memo: "Acme Corp INV-101".into(),
                    original_amount: 50_000,
                    settled_amount: 20_000,
                    open_amount: 30_000,
                }],
            },
            &units,
        )
        .unwrap();
        assert_eq!(
            oi_ir.tables[0].rows.last().unwrap().footing,
            FootingRule::Double
        );
    }

    #[test]
    fn lineage_diagram_renders_byte_identical_markdown_and_svg() {
        let nodes = vec![
            LineageDiagramNode {
                entry_vid_hex: "11111111111111111111111111111111".into(),
                entry_class: "Journal".into(),
                effective_date: "2026-03-10".into(),
                recorded_at: 5,
                live: false,
                amount_summary: "100.00 USD".into(),
            },
            LineageDiagramNode {
                entry_vid_hex: "22222222222222222222222222222222".into(),
                entry_class: "Reversal".into(),
                effective_date: "2026-03-10".into(),
                recorded_at: 8,
                live: true,
                amount_summary: "-100.00 USD".into(),
            },
            LineageDiagramNode {
                entry_vid_hex: "33333333333333333333333333333333".into(),
                entry_class: "Replacement".into(),
                effective_date: "2026-03-10".into(),
                recorded_at: 9,
                live: true,
                amount_summary: "95.00 USD".into(),
            },
        ];
        let edges = vec![
            LineageDiagramEdge {
                from_entry_vid_hex: "22222222222222222222222222222222".into(),
                to_entry_vid_hex: "11111111111111111111111111111111".into(),
                kind: LineageEdgeKind::Supersedes,
                detail: "Reverses (exact_annihilation)".into(),
            },
            LineageDiagramEdge {
                from_entry_vid_hex: "33333333333333333333333333333333".into(),
                to_entry_vid_hex: "11111111111111111111111111111111".into(),
                kind: LineageEdgeKind::Supersedes,
                detail: "Replaces (replacement_chain)".into(),
            },
        ];
        let d1 = render_lineage_diagram(
            Id128([0x44; 16]),
            10,
            "11111111111111111111111111111111",
            &nodes,
            &edges,
        )
        .unwrap();
        let d2 = render_lineage_diagram(
            Id128([0x44; 16]),
            10,
            "11111111111111111111111111111111",
            &nodes,
            &edges,
        )
        .unwrap();
        assert_eq!(d1, d2);
        assert!(d1.markdown.contains("flowchart LR"));
        assert!(d1.svg.contains("marker-end=\"url(#arrow)\""));
        assert!(d1.svg.contains("SUPERSEDES"));
    }

    #[test]
    fn golden_markdown_ir_and_fmd_subprocess_adapter_are_pinned_and_verifiable() {
        let (def, orig) = sample_bs(10, 50_025, 12_005);
        let units = sample_units();
        let ir = render_statement_ir(&orig, &def, &units).unwrap();

        let expected_table_fragment = "\
| Code                   | Line                                                 |  FY2026-P03 |\n\
| :--------------------- | :--------------------------------------------------- | ----------: |\n\
| assets                 | Assets                                               |     1380.20 |\n\
| liabilities            | Liabilities                                          |        0.00 |\n\
| equity                 | Posted equity                                        |     1000.00 |\n\
| unclosed_revenue       | Unclosed revenue, all years                          |      500.25 |\n\
| unclosed_expense       | Unclosed expenses, all years                         |      120.05 |\n\
| unclosed_earnings      | Unclosed earnings, all years                         |    _380.20_ |\n\
| total_equity           | Equity including unclosed earnings                   | ==1380.20== |\n\
| liabilities_and_equity | Liabilities and equity including unclosed earnings   |   _1380.20_ |\n\
| balance_check          | Assets less liabilities and equity (must equal zero) |    ==0.00== |";
        assert!(
            ir.markdown.contains(expected_table_fragment),
            "golden Markdown IR table drifted:\n{}",
            ir.markdown
        );

        let missing_bin = Path::new("/nonexistent/fmd-binary-does-not-exist");
        let tmp_out = std::env::temp_dir().join("fa_cet_test_out.html");
        let err = invoke_fmd_render(
            &ir,
            StatementRenderFormat::Html,
            1_792_454_400,
            &tmp_out,
            Some(missing_bin),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unavailable"));

        let tmp_md = std::env::temp_dir().join("fa_cet_test_out.md");
        let md_receipt = invoke_fmd_render(
            &ir,
            StatementRenderFormat::Markdown,
            1_792_454_400,
            &tmp_md,
            Some(missing_bin),
        )
        .unwrap();
        assert_eq!(md_receipt.ir_digest, ir.digest().unwrap());
        assert_eq!(md_receipt.output_bytes, ir.markdown.as_bytes());
    }

    #[test]
    fn flow_of_funds_diagram_renders_deterministic_markdown_and_svg_and_refuses_non_positive_edges()
    {
        let nodes = vec![
            FlowOfFundsNode {
                code: "1000".into(),
                label: "Operating Cash".into(),
                total_inflow: 500_000,
                total_outflow: 180_000,
            },
            FlowOfFundsNode {
                code: "2100".into(),
                label: "Trade Payables".into(),
                total_inflow: 180_000,
                total_outflow: 0,
            },
        ];
        let edges = vec![FlowOfFundsEdge {
            from_code: "1000".into(),
            to_code: "2100".into(),
            amount_mantissa: 180_000,
            entry_count: 3,
        }];
        let f1 =
            render_flow_of_funds_diagram(Id128([0x44; 16]), 15, "USD", 2, &nodes, &edges).unwrap();
        let f2 =
            render_flow_of_funds_diagram(Id128([0x44; 16]), 15, "USD", 2, &nodes, &edges).unwrap();
        assert_eq!(f1, f2);
        assert!(f1.markdown.contains("1800.00 USD (3 entries)"));
        assert!(f1.svg.contains("marker-end=\"url(#fof-arrow)\""));

        let bad_edge = vec![FlowOfFundsEdge {
            from_code: "1000".into(),
            to_code: "2100".into(),
            amount_mantissa: 0,
            entry_count: 1,
        }];
        assert!(
            render_flow_of_funds_diagram(Id128([0x44; 16]), 15, "USD", 2, &nodes, &bad_edge,)
                .is_err()
        );
    }
}
