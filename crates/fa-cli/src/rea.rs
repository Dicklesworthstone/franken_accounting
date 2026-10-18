//! REA parties, instruments and relationships on the CLI (plan §4.1, §4.5,
//! §9.1). The kernel journals each one as a SchemaChange control under
//! `schema_change` authority. Until now only the library and the demo could
//! create them, so on a real book `fa event record --participant`,
//! `--resource …:<instrument>` and the related-party graph procedures had
//! nothing to name. Names and identifiers are sealed with the book's key,
//! as event external ids are; a party's name is untrusted text when read
//! back.

use std::collections::BTreeMap;

use fa_model::{
    ExternalId, InstrumentKind, InstrumentSpec, OwnershipPct, PartyKind, PartySpec,
    RelationshipKind, RelationshipSpec, account_vid,
};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, date_flag, parse_json, untrusted_text_json, usage};
use crate::json::{Json, obj, s};

const PARTY_EXAMPLE: &str = "fa party add <party.json|-> | fa party relate <from> <to> --kind owns|controls|related --basis <code> --valid-from YYYY-MM-DD [--valid-to YYYY-MM-DD] [--pct <num>/<den>] | fa party list";
const INSTRUMENT_EXAMPLE: &str = "fa instrument add <instrument.json|-> | fa instrument list";

pub(crate) fn party_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("add") => party_add(ctx, args),
        Some("relate") => party_relate(ctx, args),
        Some("list") => party_list(ctx, args),
        _ => Err(usage(
            "party has the subcommands add, relate and list",
            PARTY_EXAMPLE,
        )),
    }
}

pub(crate) fn instrument_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("add") => instrument_add(ctx, args),
        Some("list") => instrument_list(ctx, args),
        _ => Err(usage(
            "instrument has the subcommands add and list",
            INSTRUMENT_EXAMPLE,
        )),
    }
}

/// The one JSON object an `add` reads, with its fields checked against
/// `allowed` so a misspelled field is a usage error, never ignored.
fn read_object(ctx: &Ctx<'_>, args: &Args, allowed: &[&str], example: &str) -> Result<Json, Fail> {
    let [_, _, path] = args.positional.as_slice() else {
        return Err(usage("add needs one JSON file (or - for stdin)", example));
    };
    let doc = parse_json(path, &ctx.files.read_text(path)?)?;
    let Json::Obj(fields) = &doc else {
        return Err(usage(format!("{path} must be one JSON object"), example));
    };
    if let Some((field, _)) = fields.iter().find(|(f, _)| !allowed.contains(&f.as_str())) {
        return Err(usage(
            format!("{path}: unknown field `{field}`"),
            format!("fields: {}", allowed.join(", ")),
        ));
    }
    Ok(doc)
}

fn required<'a>(doc: &'a Json, field: &str, example: &str) -> Result<&'a str, Fail> {
    doc.get(field)
        .and_then(Json::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            usage(
                format!("`{field}` is required (a non-empty string)"),
                example,
            )
        })
}

fn party_kind(name: &str) -> Result<PartyKind, Fail> {
    (1..=u8::MAX)
        .map_while(PartyKind::from_tag)
        .find(|k| k.name().eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            let names: Vec<&str> = (1..=u8::MAX)
                .map_while(PartyKind::from_tag)
                .map(PartyKind::name)
                .collect();
            usage(
                format!("unknown party kind `{name}`"),
                format!("kind: {}", names.join("|")),
            )
        })
}

fn instrument_kind(name: &str) -> Result<InstrumentKind, Fail> {
    (1..=u8::MAX)
        .map_while(InstrumentKind::from_tag)
        .find(|k| k.name().eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            let names: Vec<&str> = (1..=u8::MAX)
                .map_while(InstrumentKind::from_tag)
                .map(InstrumentKind::name)
                .collect();
            usage(
                format!("unknown instrument kind `{name}`"),
                format!("kind: {}", names.join("|")),
            )
        })
}

/// `external_ids: [{"system": "...", "id": "..."}]`, sealed and in the
/// kernel's order (`(system, field_digest)`).
fn external_ids(book: &fa::Book, doc: &Json) -> Result<Vec<ExternalId>, Fail> {
    let rows = match doc.get("external_ids") {
        None | Some(Json::Null) => return Ok(Vec::new()),
        Some(Json::Arr(rows)) => rows,
        Some(_) => {
            return Err(usage(
                "`external_ids` must be an array",
                "external_ids: [{\"system\": \"qbo\", \"id\": \"55\"}]",
            ));
        }
    };
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        let (Some(system), Some(id)) = (
            row.get("system").and_then(Json::as_str),
            row.get("id").and_then(Json::as_str),
        ) else {
            return Err(usage(
                "each external id is {\"system\": \"...\", \"id\": \"...\"}",
                "external_ids: [{\"system\": \"qbo\", \"id\": \"55\"}]",
            ));
        };
        ids.push(ExternalId {
            system: system.to_string(),
            id: book.seal_text(id)?,
        });
    }
    ids.sort_by(|a, b| (&a.system, a.id.field_digest()).cmp(&(&b.system, b.id.field_digest())));
    Ok(ids)
}

/// A party (or legal entity) named by code, or by its 32-hex vertex id.
fn party_ref(book: &fa::Book, raw: &str) -> Result<VId, Fail> {
    let stripped = raw.strip_prefix("P:").unwrap_or(raw);
    if stripped.len() == 32
        && let Ok(v) = u128::from_str_radix(stripped, 16)
    {
        return Ok(VId(v));
    }
    let rea = book.rea_snapshot(None)?;
    rea.parties
        .values()
        .find(|p| p.code == stripped)
        .map(|p| p.vid)
        .or_else(|| {
            rea.legal_entities
                .values()
                .find(|e| e.code == stripped)
                .map(|e| e.vid)
        })
        .ok_or_else(|| {
            usage(
                format!("no party or legal entity `{stripped}` in this book"),
                "fa party list --json names the parties; fa party add records one",
            )
        })
}

fn emit_recorded(
    out: &Out,
    book: &fa::Book,
    object: &str,
    code: &str,
    recorded: &fa_journal::ReaControlRecorded,
) -> Result<(), Fail> {
    out.at_book(book)?;
    out.event(
        "rea_recorded",
        vec![
            ("object", s(object)),
            ("code", s(code)),
            ("target", s(format!("{:032x}", recorded.target_vid.0))),
            (
                "control_entry",
                s(format!("{:032x}", recorded.control_entry.0)),
            ),
            ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
        ],
        &format!(
            "{object} {code} recorded as {:032x} (control entry {:032x}, recorded at {}){}",
            recorded.target_vid.0,
            recorded.control_entry.0,
            recorded.recorded_at.0,
            if recorded.already_recorded {
                "; already recorded, nothing new was written"
            } else {
                ""
            },
        ),
    );
    Ok(())
}

fn party_add(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const FIX: &str = "{\"code\": \"V-17\", \"kind\": \"Vendor\", \"name\": \"Acme Supplies\", \"identifiers\": {\"ein\": \"12-3456789\"}, \"external_ids\": [{\"system\": \"qbo\", \"id\": \"55\"}]}";
    let doc = read_object(
        ctx,
        args,
        &["code", "kind", "name", "identifiers", "external_ids"],
        FIX,
    )?;
    let code = required(&doc, "code", FIX)?.to_string();
    let kind = party_kind(required(&doc, "kind", FIX)?)?;
    let name = required(&doc, "name", FIX)?.to_string();
    let mut identifiers: BTreeMap<String, String> = BTreeMap::new();
    match doc.get("identifiers") {
        None | Some(Json::Null) => {}
        Some(Json::Obj(fields)) => {
            for (key, value) in fields {
                let Some(value) = value.as_str() else {
                    return Err(usage(format!("identifier `{key}` must be a string"), FIX));
                };
                identifiers.insert(key.clone(), value.to_string());
            }
        }
        Some(_) => return Err(usage("`identifiers` must be an object of strings", FIX)),
    }
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open(args)?;
    let mut sealed = Vec::with_capacity(identifiers.len());
    for (key, value) in &identifiers {
        sealed.push((key.clone(), book.seal_text(value)?));
    }
    let spec = PartySpec {
        code: code.clone(),
        kind,
        name: book.seal_text(&name)?,
        identifiers: sealed,
        external_ids: external_ids(&book, &doc)?,
    };
    let key = args
        .flag("--key")
        .map_or_else(|| format!("party:{code}"), str::to_string);
    let date = date_flag(args, DateDay(0))?;
    let recorded = book.create_party(&spec, who, date, key.as_bytes(), &capability)??;
    emit_recorded(&ctx.out, &book, "party", &code, &recorded)
}

fn instrument_add(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const FIX: &str = "{\"code\": \"BA-1\", \"name\": \"Operating account\", \"kind\": \"BankAccount\", \"unit\": \"USD\", \"held_at\": \"BANK-1\", \"mirrors\": \"1000\"}";
    let doc = read_object(
        ctx,
        args,
        &[
            "code",
            "name",
            "kind",
            "unit",
            "held_at",
            "mirrors",
            "external_ids",
        ],
        FIX,
    )?;
    let code = required(&doc, "code", FIX)?.to_string();
    let name = required(&doc, "name", FIX)?.to_string();
    let kind = instrument_kind(required(&doc, "kind", FIX)?)?;
    let unit_code = required(&doc, "unit", FIX)?;
    let held_at = required(&doc, "held_at", FIX)?;
    let mirrors = required(&doc, "mirrors", FIX)?;
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open(args)?;
    let book_id = book.context().book_id;
    let unit = book.context().units.lookup(unit_code).ok_or_else(|| {
        usage(
            format!("unknown unit `{unit_code}`"),
            "unit: a registered unit code such as USD",
        )
    })?;
    if !book.accounts()?.iter().any(|a| a.code == mirrors) {
        return Err(usage(
            format!("no account `{mirrors}` in this book"),
            "mirrors: the GL leaf account this instrument mirrors (fa chart list --json)",
        ));
    }
    let spec = InstrumentSpec {
        code: code.clone(),
        name,
        kind,
        unit,
        held_at_party: party_ref(&book, held_at)?,
        mirrors_account: account_vid(book_id, mirrors),
        external_ids: external_ids(&book, &doc)?,
    };
    let key = args
        .flag("--key")
        .map_or_else(|| format!("instrument:{code}"), str::to_string);
    let date = date_flag(args, DateDay(0))?;
    let recorded = book.create_instrument(&spec, who, date, key.as_bytes(), &capability)??;
    emit_recorded(&ctx.out, &book, "instrument", &code, &recorded)
}

fn party_relate(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, from, to] = args.positional.as_slice() else {
        return Err(usage("party relate needs <from> and <to>", PARTY_EXAMPLE));
    };
    for flag in [
        "--kind",
        "--basis",
        "--valid-from",
        "--valid-to",
        "--pct",
        "--key",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("party relate takes only one {flag}"),
                PARTY_EXAMPLE,
            ));
        }
    }
    let day = |flag: &str| -> Result<Option<DateDay>, Fail> {
        args.flag(flag)
            .map(|text| {
                DateDay::parse(text)
                    .map_err(|e| usage(format!("{flag} `{text}`: {e:?}"), "YYYY-MM-DD"))
            })
            .transpose()
    };
    let valid_from = day("--valid-from")?.ok_or_else(|| {
        usage(
            "party relate needs --valid-from YYYY-MM-DD (no date defaults to today)",
            PARTY_EXAMPLE,
        )
    })?;
    let valid_to = day("--valid-to")?;
    let basis = args
        .flag("--basis")
        .ok_or_else(|| {
            usage(
                "party relate needs --basis <code> from relationship_bases.toml",
                "--basis equity_voting | beneficial_ownership | majority_voting_control | common_control | …",
            )
        })?
        .to_string();
    let kind_name = args.flag("--kind").unwrap_or("");
    let kind = match (kind_name, args.flag("--pct")) {
        ("owns", Some(pct)) => {
            let ratio = pct
                .split_once('/')
                .and_then(|(n, d)| {
                    Some((
                        n.trim().parse::<i128>().ok()?,
                        d.trim().parse::<u128>().ok()?,
                    ))
                })
                .and_then(|(n, d)| OwnershipPct::new(n, d))
                .ok_or_else(|| {
                    usage(
                        format!("--pct `{pct}` is not an exact ownership ratio in (0, 1]"),
                        "--pct 51/100 (an exact rational, never a float)",
                    )
                })?;
            RelationshipKind::Owns { pct: ratio }
        }
        ("owns", None) => {
            return Err(usage(
                "an owns relationship needs --pct <num>/<den>",
                "--pct 51/100",
            ));
        }
        ("controls" | "related", Some(_)) => {
            return Err(usage("--pct applies only to --kind owns", PARTY_EXAMPLE));
        }
        ("controls", None) => RelationshipKind::Controls,
        ("related", None) => RelationshipKind::RelatedTo,
        (other, _) => {
            return Err(usage(
                format!("unknown relationship kind `{other}`"),
                "--kind owns|controls|related",
            ));
        }
    };
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open(args)?;
    let spec = RelationshipSpec {
        from: party_ref(&book, from)?,
        to: party_ref(&book, to)?,
        kind,
        basis: basis.clone(),
        valid_from,
        valid_to,
    };
    let key = args.flag("--key").map_or_else(
        || {
            format!(
                "relationship:{from}:{to}:{kind_name}:{basis}:{}",
                valid_from.render()
            )
        },
        str::to_string,
    );
    let date = date_flag(args, DateDay(0))?;
    let recorded = book.record_relationship(&spec, who, date, key.as_bytes(), &capability)??;
    emit_recorded(
        &ctx.out,
        &book,
        "relationship",
        &format!("{from}->{to}"),
        &recorded,
    )
}

fn party_list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "party list takes no argument",
            "fa party list --json",
        ));
    }
    let book = ctx.books.open(args)?;
    let rea = book.rea_snapshot(None)?;
    let key = &book.context().seal_key;
    let mut parties: Vec<_> = rea.parties.values().collect();
    parties.sort_by(|a, b| a.code.cmp(&b.code));
    let rows: Vec<Json> = parties
        .iter()
        .map(|p| {
            obj(vec![
                ("code", s(&p.code)),
                ("kind", s(p.kind.name())),
                ("vid", s(format!("{:032x}", p.vid.0))),
                (
                    "name",
                    untrusted_text_json(
                        p.name
                            .open(key, fa_model::limits::MAX_DESCRIPTION_BYTES)
                            .ok(),
                        format!("P:{:032x}", p.vid.0),
                    ),
                ),
                ("created_at", Json::Int(i128::from(p.created_at.0))),
            ])
        })
        .collect();
    let human: Vec<String> = parties
        .iter()
        .map(|p| format!("{:<16} {:<16} {:032x}", p.code, p.kind.name(), p.vid.0))
        .collect();
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "parties",
        vec![
            ("known_at", Json::Int(i128::from(rea.known_at.0))),
            ("parties", Json::Arr(rows)),
            ("relationships", Json::Int(rea.relationships.len() as i128)),
        ],
        &human.join("\n"),
    );
    Ok(())
}

fn instrument_list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "instrument list takes no argument",
            "fa instrument list --json",
        ));
    }
    let book = ctx.books.open(args)?;
    let rea = book.rea_snapshot(None)?;
    let units = &book.context().units;
    let mut instruments: Vec<_> = rea.instruments.values().collect();
    instruments.sort_by(|a, b| a.code.cmp(&b.code));
    let rows: Vec<Json> = instruments
        .iter()
        .map(|i| {
            obj(vec![
                ("code", s(&i.code)),
                ("name", s(&i.name)),
                ("kind", s(i.kind.name())),
                (
                    "unit",
                    units.get(i.unit).map_or(Json::Null, |u| s(u.code.as_str())),
                ),
                ("vid", s(format!("{:032x}", i.vid.0))),
                ("held_at", s(format!("{:032x}", i.held_at_party.0))),
                ("mirrors", s(format!("{:032x}", i.mirrors_account.0))),
                ("created_at", Json::Int(i128::from(i.created_at.0))),
            ])
        })
        .collect();
    let human: Vec<String> = instruments
        .iter()
        .map(|i| format!("{:<16} {:<16} {}", i.code, i.kind.name(), i.name))
        .collect();
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "instruments",
        vec![
            ("known_at", Json::Int(i128::from(rea.known_at.0))),
            ("instruments", Json::Arr(rows)),
        ],
        &human.join("\n"),
    );
    Ok(())
}
