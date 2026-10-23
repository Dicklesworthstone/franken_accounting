//! Dimensions on the CLI (plan §4.1, bead fa-ficc). `fa dimension add`
//! journals one value of a registered dimension (cost center, department,
//! project and the other kinds in `fa_model::DIMENSION_KINDS`), `fa
//! dimension list` lists them, and a post intent's leg tags values with
//! `"dimensions": {"cost_center": "CC10"}`. The kernel checks each tagged
//! value exists in its dimension and is effective on the entry's date.

use fa::dimension::{DimensionValueRow, DimensionValueSpec};
use fa_model::{Id128, dimension_kind, dimension_value_vid};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Ctx, Fail, known_at_read_flag, usage};
use crate::json::{Json, obj, s};

const ADD: &str = "fa dimension add <dimension> <code> --name <name> [--parent <code>] [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--key K]";
const LIST: &str = "fa dimension list [<dimension>] [--as-known-at HEAD|<seq>]";

fn kinds() -> String {
    fa_journal::dimension::kinds_listing()
}

/// The code of the dimension a `dimension_set` entry names by id.
pub(crate) fn code_of(id: u32) -> &'static str {
    match id {
        fa_model::LEGAL_ENTITY_DIMENSION => fa_model::LEGAL_ENTITY_DIMENSION_CODE,
        fa_model::PARTY_DIMENSION => fa_model::PARTY_DIMENSION_CODE,
        other => fa_model::dimension_kind_of(other).map_or("unregistered", |kind| kind.code),
    }
}

pub(crate) fn dimension_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("add") => add(ctx, args),
        Some("list") => list(ctx, args),
        _ => Err(usage(
            "dimension has the subcommands add and list",
            format!("{ADD} | {LIST}"),
        )),
    }
}

/// One `dimension_value` object (verbs.toml shape).
fn value_json(row: &DimensionValueRow) -> Json {
    let day = |day: Option<DateDay>| day.map_or(Json::Null, |day| s(day.render()));
    obj(vec![
        ("dimension", s(&row.spec.dimension)),
        ("code", s(&row.spec.code)),
        ("name", s(&row.spec.name)),
        ("parent", row.spec.parent.as_ref().map_or(Json::Null, s)),
        ("valid_from", day(row.spec.valid_from)),
        ("valid_to", day(row.spec.valid_to)),
        ("dimension_id", Json::Int(i128::from(row.dimension_id))),
        ("vid", s(format!("{:032x}", row.vid.0))),
        ("recorded_at", Json::Int(i128::from(row.created_at.0))),
    ])
}

fn window(row: &DimensionValueRow) -> String {
    match (row.spec.valid_from, row.spec.valid_to) {
        (None, None) => "always".into(),
        (Some(from), None) => format!("from {}", from.render()),
        (None, Some(to)) => format!("before {}", to.render()),
        (Some(from), Some(to)) => format!("{} to {}", from.render(), to.render()),
    }
}

fn registered(dimension: &str, example: &str) -> Result<(), Fail> {
    if dimension_kind(dimension).is_none() {
        return Err(usage(
            format!("`{dimension}` is not a registered dimension"),
            format!("name one of: {} ({example})", kinds()),
        ));
    }
    Ok(())
}

/// `fa dimension add <dimension> <code> --name <name> …`.
fn add(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, dimension, code] = args.positional.as_slice() else {
        return Err(usage(
            "dimension add names one dimension and one value code",
            ADD,
        ));
    };
    registered(dimension, ADD)?;
    let Some(name) = args.flag("--name") else {
        return Err(usage("dimension add needs --name", ADD));
    };
    let day = |flag: &str| -> Result<Option<DateDay>, Fail> {
        args.flag(flag)
            .map(|text| {
                DateDay::parse(text)
                    .map_err(|e| usage(format!("{flag} `{text}`: {e:?}"), "YYYY-MM-DD"))
            })
            .transpose()
    };
    let spec = DimensionValueSpec {
        dimension: dimension.clone(),
        code: code.clone(),
        name: name.to_string(),
        parent: args.flag("--parent").map(str::to_string),
        valid_from: day("--from")?,
        valid_to: day("--to")?,
    };
    if let Some(problem) = spec.problem() {
        return Err(usage(problem, ADD));
    }
    let key = args
        .flag("--key")
        .map_or_else(|| format!("dimension:{dimension}:{code}"), str::to_string);
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &capability)??;
        Ok(())
    })?;
    let recorded = book.create_dimension_value(&spec, who, key.as_bytes(), &capability)??;
    ctx.out.at_book(&book)?;
    let value = &recorded.value;
    ctx.out.event(
        "dimension_value_recorded",
        vec![
            ("value", value_json(value)),
            (
                "control_entry",
                s(format!("{:032x}", recorded.control_entry.0)),
            ),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
        ],
        &format!(
            "{} {} ({}), effective {}{}{} (control {:032x}, recorded at {})",
            value.spec.dimension,
            value.spec.code,
            value.spec.name,
            window(value),
            value
                .spec
                .parent
                .as_ref()
                .map_or_else(String::new, |parent| format!(", under {parent}")),
            if recorded.already_recorded {
                "; nothing was written"
            } else {
                ""
            },
            recorded.control_entry.0,
            value.created_at.0,
        ),
    );
    Ok(())
}

/// `fa dimension list [<dimension>] [--as-known-at …]`.
fn list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let only = match args.positional.as_slice() {
        [_, _] => None,
        [_, _, dimension] => {
            registered(dimension, LIST)?;
            Some(dimension.as_str())
        }
        _ => {
            return Err(usage("dimension list takes at most one dimension", LIST));
        }
    };
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    let (at, values) = book.dimension_values(known_at, &cap)??;
    let values: Vec<&DimensionValueRow> = values
        .iter()
        .filter(|row| only.is_none_or(|only| row.spec.dimension == only))
        .collect();
    let human: Vec<String> = values
        .iter()
        .map(|row| {
            format!(
                "{:<12} {:<12} {:<32} {:<12} {}",
                row.spec.dimension,
                row.spec.code,
                row.spec.name,
                row.spec.parent.as_deref().unwrap_or("-"),
                window(row)
            )
        })
        .collect();
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "dimension_values",
        vec![
            ("known_at", Json::Int(i128::from(at.0))),
            ("dimension", only.map_or(Json::Null, s)),
            (
                "values",
                Json::Arr(values.iter().map(|row| value_json(row)).collect()),
            ),
        ],
        &if human.is_empty() {
            format!(
                "no dimension values; create one with {ADD} (dimensions: {})",
                kinds()
            )
        } else {
            human.join("\n")
        },
    );
    Ok(())
}

/// A leg's `"dimensions": {"cost_center": "CC10", …}` as `dimension_set`
/// entries. The legal entity and the party keep their own `entity` and
/// `party` fields.
pub(crate) fn leg_dimensions(leg: &Json, what: &str, book: Id128) -> Result<Vec<(u32, VId)>, Fail> {
    const EXAMPLE: &str = "\"dimensions\": {\"cost_center\": \"CC10\", \"project\": \"P-7\"}";
    let fields = match leg.get("dimensions") {
        None | Some(Json::Null) => return Ok(Vec::new()),
        Some(Json::Obj(fields)) => fields,
        Some(_) => {
            return Err(usage(
                format!("{what}: `dimensions` must be an object of value codes"),
                EXAMPLE,
            ));
        }
    };
    let mut out = Vec::with_capacity(fields.len());
    for (dimension, value) in fields {
        let Some(kind) = dimension_kind(dimension) else {
            let fix = match dimension.as_str() {
                "legal_entity" | "entity" => {
                    "name the legal entity in the leg's `entity` field".to_string()
                }
                "party" => "name the party in the leg's `party` field".to_string(),
                _ => format!("the dimensions are {}", kinds()),
            };
            return Err(usage(
                format!("{what}: `{dimension}` is not a registered dimension"),
                fix,
            ));
        };
        let Some(code) = value.as_str().filter(|code| !code.is_empty()) else {
            return Err(usage(
                format!("{what}: dimensions.{dimension} must be a non-empty value code"),
                EXAMPLE,
            ));
        };
        if out.iter().any(|(id, _)| *id == kind.id) {
            return Err(usage(
                format!("{what}: dimensions names `{dimension}` twice"),
                "a leg carries one value of each dimension",
            ));
        }
        out.push((kind.id, dimension_value_vid(book, kind.code, code)));
    }
    Ok(out)
}
