//! Shared presentation for live and replayed native lot schedules.

use fa::{Book, LotsReport};
use fa_model::{Id128, dimension_kind, dimension_value_vid};
use fa_money::Side;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{
    Fail, Out, hex, plan_dimensions_json, registered_unit_code, render_amount, usage,
};
use crate::json::{Json, obj, s};

/// An exact lot partition, never a subtree or a partial-dimension filter.
/// The posting kernel authenticates each selected identity and its valid time.
pub(crate) fn dimensions(args: &Args, book: Id128) -> Result<Vec<(u32, VId)>, Fail> {
    const EXAMPLE: &str = "--dimension legal_entity:PARENT --dimension cost_center:WAREHOUSE";
    let mut selected = std::collections::BTreeMap::new();
    for raw in args.flag_all("--dimension") {
        let (code, value) = raw
            .split_once(':')
            .filter(|(_, value)| !value.is_empty())
            .ok_or_else(|| usage("--dimension requires KIND:VALUE", EXAMPLE))?;
        let id = match code {
            fa_model::LEGAL_ENTITY_DIMENSION_CODE => fa_model::LEGAL_ENTITY_DIMENSION,
            fa_model::PARTY_DIMENSION_CODE => fa_model::PARTY_DIMENSION,
            other => dimension_kind(other)
                .map(|kind| kind.id)
                .ok_or_else(|| usage(format!("unknown lot dimension `{other}`"), EXAMPLE))?,
        };
        if selected
            .insert(id, dimension_value_vid(book, code, value))
            .is_some()
        {
            return Err(usage(
                "an exact lot partition names each dimension once",
                EXAMPLE,
            ));
        }
    }
    if selected.len() > fa_model::limits::MAX_DIMENSIONS_PER_LEG {
        return Err(usage(
            "the lot partition exceeds the dimension bound",
            EXAMPLE,
        ));
    }
    Ok(selected.into_iter().collect())
}

pub(crate) fn render(
    out: &Out,
    book: &Book,
    report: &LotsReport,
    disposal_plan: Option<Json>,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let units = &book.context().units;
    let base_unit_code = registered_unit_code(report.base_unit, units)?;
    let lots: Vec<Json> = report
        .lots
        .iter()
        .map(|lot| {
            let relieves: Vec<Json> = lot
                .relieves
                .iter()
                .map(|relief| {
                    Ok(obj(vec![
                        (
                            "disposal_entry",
                            s(format!("{:032x}", relief.disposal_entry.0)),
                        ),
                        (
                            "qty_ordinal",
                            relief
                                .qty_ordinal
                                .map_or(Json::Null, |q| Json::Int(i128::from(q))),
                        ),
                        (
                            "cost_ordinal",
                            relief
                                .cost_ordinal
                                .map_or(Json::Null, |c| Json::Int(i128::from(c))),
                        ),
                        ("quantity", s(render_amount(relief.quantity, units)?)),
                        ("cost", s(render_amount(relief.cost, units)?)),
                        ("recorded_at", Json::Int(i128::from(relief.recorded_at.0))),
                        ("live", Json::Bool(relief.live)),
                    ]))
                })
                .collect::<Result<_, Fail>>()?;
            Ok(obj(vec![
                ("entry", s(format!("{:032x}", lot.entry.0))),
                ("entry_digest", s(hex(&lot.entry_digest))),
                ("qty_ordinal", Json::Int(i128::from(lot.qty_ordinal))),
                ("cost_ordinal", Json::Int(i128::from(lot.cost_ordinal))),
                ("dimensions", plan_dimensions_json(&lot.dimensions)),
                (
                    "side",
                    s(match lot.side {
                        Side::Debit => "debit",
                        Side::Credit => "credit",
                    }),
                ),
                ("effective_date", s(lot.effective_date.render())),
                ("recorded_at", Json::Int(i128::from(lot.recorded_at.0))),
                (
                    "original_quantity",
                    s(render_amount(lot.original_quantity, units)?),
                ),
                (
                    "relieved_quantity",
                    s(render_amount(lot.relieved_quantity, units)?),
                ),
                ("open_quantity", s(render_amount(lot.open_quantity, units)?)),
                ("original_cost", s(render_amount(lot.original_cost, units)?)),
                ("relieved_cost", s(render_amount(lot.relieved_cost, units)?)),
                ("open_cost", s(render_amount(lot.open_cost, units)?)),
                ("relieves", Json::Arr(relieves)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    out.known_at(report.known_at);
    if let Some(day) = report.effective_through {
        out.effective(format!("as-of:{day}"));
    }
    out.event_with_certificate(
        "lots",
        vec![
            ("account", s(&report.account_code)),
            ("account_vid", s(format!("{:032x}", report.account.0))),
            ("name", s(&report.account_name)),
            ("base_unit", s(&base_unit_code)),
            ("known_at", Json::Int(i128::from(report.known_at.0))),
            (
                "effective_through",
                report
                    .effective_through
                    .map_or(Json::Null, |day| s(day.render())),
            ),
            ("count", Json::Int(report.lots.len() as i128)),
            ("lots", Json::Arr(lots)),
            ("disposal_plan", disposal_plan.unwrap_or(Json::Null)),
        ],
        &format!(
            "lots for {} ({}) at {}: {} lot(s)",
            report.account_code,
            report.account_name,
            report.known_at.0,
            report.lots.len()
        ),
        certificate,
    );
    Ok(())
}
