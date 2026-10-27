//! `fa law list|show` and `fa unit list` (plan §6.2–§6.4, Appendix D
//! "Chart and registries"): the registered laws and unit versions this
//! build embeds, so an agent can discover a law's or a unit's registered
//! name before an intent names it. They read no book.

use fa_registry::toml::{self, Table, Value};

use crate::args::Args;
use crate::cli::{Ctx, Fail, usage};
use crate::json::{Json, obj, s};

const LAW_EXAMPLE: &str = "fa law list [--family rounding|allocation|proportional-post|conversion|fx|lot|tracing] --json; fa law show <name> [--family <family>] --json";

/// One registered law: its family, id, name and version, and every other
/// field of its registry row as text, in key order.
struct LawRow {
    family: &'static str,
    id: i128,
    name: String,
    version: Option<i128>,
    attributes: Vec<(String, String)>,
}

fn text(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(items) => items.iter().map(text).collect::<Vec<_>>().join(", "),
    }
}

fn registry_error(what: &str, e: impl std::fmt::Display) -> Fail {
    Fail::Internal(format!("{what}: {e}"))
}

fn law_rows() -> Result<Vec<LawRow>, Fail> {
    let mut out = Vec::new();
    for (family, array, source) in fa_registry::LAW_REGISTRIES {
        let doc = toml::parse(source).map_err(|e| registry_error(family, e))?;
        for row in doc.arrays.get(array).map(Vec::as_slice).unwrap_or_default() {
            out.push(law_row(family, row)?);
        }
    }
    Ok(out)
}

fn law_row(family: &'static str, row: &Table) -> Result<LawRow, Fail> {
    let id = row
        .get("id")
        .and_then(Value::as_int)
        .ok_or_else(|| registry_error(family, "a law row has no integer id"))?;
    let name = row
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| registry_error(family, "a law row has no name"))?
        .to_string();
    let version = row.get("version").and_then(Value::as_int);
    let attributes = row
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "id" | "name" | "version"))
        .map(|(k, v)| (k.clone(), text(v)))
        .collect();
    Ok(LawRow {
        family,
        id,
        name,
        version,
        attributes,
    })
}

fn law_json(row: &LawRow) -> Json {
    obj(vec![
        ("family", s(row.family)),
        ("id", Json::Int(row.id)),
        ("name", s(&row.name)),
        ("version", row.version.map_or(Json::Null, Json::Int)),
        (
            "attributes",
            Json::Arr(
                row.attributes
                    .iter()
                    .map(|(k, v)| obj(vec![("key", s(k)), ("value", s(v))]))
                    .collect(),
            ),
        ),
    ])
}

fn families() -> Vec<&'static str> {
    fa_registry::LAW_REGISTRIES
        .iter()
        .map(|(family, _, _)| *family)
        .collect()
}

fn family(args: &Args) -> Result<Option<&str>, Fail> {
    if args.flag_all("--family").len() > 1 {
        return Err(usage("--family is given once", LAW_EXAMPLE));
    }
    match args.flag("--family") {
        Some(f) if !families().contains(&f) => Err(usage(
            format!("--family `{f}` is not a law family"),
            format!("--family {}", families().join("|")),
        )),
        other => Ok(other),
    }
}

pub(crate) fn law_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("list") if args.positional.len() == 2 => {
            let family = family(args)?;
            let rows: Vec<LawRow> = law_rows()?
                .into_iter()
                .filter(|r| family.is_none_or(|f| r.family == f))
                .collect();
            let human = rows
                .iter()
                .map(|r| format!("{:<10} {:>3} {}", r.family, r.id, r.name))
                .collect::<Vec<_>>()
                .join("\n");
            ctx.out.event(
                "laws",
                vec![("laws", Json::Arr(rows.iter().map(law_json).collect()))],
                &human,
            );
            Ok(())
        }
        Some("show") if args.positional.len() == 3 => {
            let name = args.positional[2].as_str();
            let family = family(args)?;
            let all = law_rows()?;
            let mut found: Vec<&LawRow> = all
                .iter()
                .filter(|r| r.name == name && family.is_none_or(|f| r.family == f))
                .collect();
            match found.len() {
                1 => {
                    let row = found.remove(0);
                    let mut human = format!(
                        "{} law {} (id {}{})",
                        row.family,
                        row.name,
                        row.id,
                        row.version
                            .map_or_else(String::new, |v| format!(", version {v}"))
                    );
                    for (k, v) in &row.attributes {
                        human.push_str(&format!("\n  {k}: {v}"));
                    }
                    ctx.out.event("law", vec![("law", law_json(row))], &human);
                    Ok(())
                }
                0 => {
                    let mut names: Vec<&str> = all.iter().map(|r| r.name.as_str()).collect();
                    names.sort_unstable();
                    names.dedup();
                    Err(usage(
                        format!("no registered law is named `{name}`"),
                        format!("fa law list --json; registered: {}", names.join(", ")),
                    ))
                }
                _ => Err(usage(
                    format!(
                        "`{name}` names a law in several families ({}); name one with --family",
                        found
                            .iter()
                            .map(|r| r.family)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    LAW_EXAMPLE,
                )),
            }
        }
        _ => Err(usage("law needs list, or show <name>", LAW_EXAMPLE)),
    }
}

pub(crate) fn unit_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("list") || args.positional.len() != 2 {
        return Err(usage("unit needs list", "fa unit list --json"));
    }
    let doc = toml::parse(fa_registry::UNITS_REGISTRY).map_err(|e| registry_error("units", e))?;
    let laws = law_rows()?;
    let rounding_name = |id: i128| {
        laws.iter()
            .find(|r| r.family == "rounding" && r.id == id)
            .map_or_else(|| id.to_string(), |r| r.name.clone())
    };
    let mut units = Vec::new();
    let mut human = Vec::new();
    for row in doc
        .arrays
        .get("unit")
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let int = |key: &str| row.get(key).and_then(Value::as_int);
        let str_of = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default();
        let (Some(id), Some(version), Some(scale)) = (int("id"), int("version"), int("scale"))
        else {
            return Err(registry_error(
                "units",
                "a unit row lacks id, version or scale",
            ));
        };
        let rounding = int("rounding_default").map(rounding_name);
        human.push(format!(
            "{:>3} {:<6} v{version} scale {scale} {}",
            id,
            str_of("code"),
            str_of("kind")
        ));
        units.push(obj(vec![
            ("id", Json::Int(id)),
            ("code", s(str_of("code"))),
            ("version", Json::Int(version)),
            ("scale", Json::Int(scale)),
            ("kind", s(str_of("kind"))),
            ("iso4217", int("iso4217").map_or(Json::Null, Json::Int)),
            ("rounding_default", rounding.map_or(Json::Null, s)),
        ]));
    }
    ctx.out.event(
        "units",
        vec![("units", Json::Arr(units))],
        &human.join("\n"),
    );
    Ok(())
}
