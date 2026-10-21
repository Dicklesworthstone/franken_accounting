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
    ExternalId, ExternalIdBinding, InstrumentKind, InstrumentSpec, LegalEntityFullSpec,
    OwnershipPct, PartyKind, PartySpec, RelationshipKind, RelationshipSpec, account_vid,
};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, date_flag, parse_json, untrusted_text_json, usage};
use crate::json::{Json, obj, s};

const PARTY_EXAMPLE: &str = "fa party add <party.json|-> | fa party relate <from> <to> --kind owns|controls|related --basis <code> --valid-from YYYY-MM-DD [--valid-to YYYY-MM-DD] [--pct <num>/<den>] | fa party bind <code> --external-id <system>:<id> | fa party ownership <owner> <target> --as-of YYYY-MM-DD | fa party list";
const INSTRUMENT_EXAMPLE: &str = "fa instrument add <instrument.json|-> | fa instrument list";
const ENTITY_EXAMPLE: &str = "fa entity add <entity.json|-> | fa entity list";

pub(crate) fn party_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("add") => party_add(ctx, args),
        Some("relate") => party_relate(ctx, args),
        Some("bind") => party_bind(ctx, args),
        Some("identifiers") => party_identifiers(ctx, args),
        Some("ownership") => party_ownership(ctx, args),
        Some("list") => party_list(ctx, args),
        _ => Err(usage(
            "party has the subcommands add, relate, bind, identifiers, ownership and list",
            PARTY_EXAMPLE,
        )),
    }
}

pub(crate) fn entity_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("add") => entity_add(ctx, args),
        Some("list") => entity_list(ctx, args),
        _ => Err(usage(
            "entity has the subcommands add and list",
            ENTITY_EXAMPLE,
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

/// Admit the whole-book read against current native authority before the
/// book's identity, frontier or contents reach any output (plan §1 rule 8).
/// These listings are not decomposed into branches, known-at, periods,
/// effective dates or accounts, so a token scoped by any of them reads none
/// of them (fail closed, as findings do).
pub(crate) fn admit_read(book: &fa::Book, who: VId, cap: &fa::Capability) -> Result<(), Fail> {
    let _ = book.read_scope(who, cap)??;
    fa_policy::reach(cap, &fa_policy::Reach::whole_book(true), None)
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))
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

/// `external_ids: [{"system": "...", "id": "..."}]` as plaintext pairs,
/// sorted, which is what a retry compares.
fn requested_ids(doc: &Json) -> Result<Vec<(String, String)>, Fail> {
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
        ids.push((system.to_string(), id.to_string()));
    }
    ids.sort();
    Ok(ids)
}

/// The requested external ids, sealed and in the kernel's order
/// (`(system, field_digest)`).
fn sealed_ids(book: &fa::Book, ids: &[(String, String)]) -> Result<Vec<ExternalId>, Fail> {
    let mut sealed = Vec::with_capacity(ids.len());
    for (system, id) in ids {
        sealed.push(ExternalId {
            system: system.clone(),
            id: book.seal_text(id)?,
        });
    }
    sealed.sort_by(|a, b| (&a.system, a.id.field_digest()).cmp(&(&b.system, b.id.field_digest())));
    Ok(sealed)
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
    let ids = requested_ids(&doc)?;
    let key = args
        .flag("--key")
        .map_or_else(|| format!("party:{code}"), str::to_string);
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &capability)??;
        Ok(())
    })?;
    let mut sealed = Vec::with_capacity(identifiers.len());
    for (field, value) in &identifiers {
        sealed.push((field.clone(), book.seal_text(value)?));
    }
    let spec = PartySpec {
        code: code.clone(),
        kind,
        name: book.seal_text(&name)?,
        identifiers: sealed,
        external_ids: sealed_ids(&book, &ids)?,
    };
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
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &capability)??;
        Ok(())
    })?;
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
    let ids = requested_ids(&doc)?;
    let key = args
        .flag("--key")
        .map_or_else(|| format!("instrument:{code}"), str::to_string);
    let held_at_party = party_ref(&book, held_at)?;
    let mirrors_account = account_vid(book_id, mirrors);
    let spec = InstrumentSpec {
        code: code.clone(),
        name,
        kind,
        unit,
        held_at_party,
        mirrors_account,
        external_ids: sealed_ids(&book, &ids)?,
    };
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
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &capability)??;
        Ok(())
    })?;
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

/// The longest OWNS chain `fa party ownership` follows unless asked.
const OWNERSHIP_DEPTH: usize = 8;

/// `fa party ownership <owner> <target> --as-of YYYY-MM-DD [--max-depth N]`
/// (plan §4.5, §11.4 related-party exposure): the owner's effective stake in
/// the target on that day, the exact sum over simple OWNS paths of at most N
/// edges of the product of their stakes, from relationships whose valid time
/// covers the day. A read of the journaled REA graph; no date defaults to
/// today, and the stake is an exact ratio.
fn party_ownership(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str =
        "fa party ownership <owner> <target> --as-of YYYY-MM-DD [--max-depth 1..=16] --json";
    let [_, _, owner_raw, target_raw] = args.positional.as_slice() else {
        return Err(usage("party ownership needs <owner> and <target>", EXAMPLE));
    };
    for flag in ["--as-of", "--max-depth"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("party ownership takes only one {flag}"),
                EXAMPLE,
            ));
        }
    }
    let as_of_text = args.flag("--as-of").ok_or_else(|| {
        usage(
            "party ownership needs --as-of YYYY-MM-DD (no date defaults to today)",
            EXAMPLE,
        )
    })?;
    let as_of = DateDay::parse(as_of_text)
        .map_err(|e| usage(format!("--as-of `{as_of_text}`: {e:?}"), "YYYY-MM-DD"))?;
    let max_depth = match args.flag("--max-depth") {
        None => OWNERSHIP_DEPTH,
        Some(text) => text
            .parse::<usize>()
            .ok()
            .filter(|depth| (1..=16).contains(depth))
            .ok_or_else(|| usage(format!("--max-depth `{text}` is not 1..=16"), EXAMPLE))?,
    };
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| admit_read(book, who, &cap))?;
    let owner = party_ref(&book, owner_raw)?;
    let target = party_ref(&book, target_raw)?;
    if owner == target {
        return Err(usage(
            "the owner and the target are the same party",
            "name two different parties or legal entities",
        ));
    }
    let rea = book.rea_snapshot(None)?;
    let stake = rea
        .effective_ownership_as_of(owner, target, as_of, max_depth)
        .ok_or_else(|| {
            usage(
                format!(
                    "the exact stake over OWNS chains of up to {max_depth} edges overflows a 128-bit ratio"
                ),
                "lower --max-depth",
            )
        })?;
    let ratio = format!("{}/{}", stake.num(), stake.den());
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "effective_ownership",
        vec![
            ("owner_vid", s(format!("{:032x}", owner.0))),
            ("target_vid", s(format!("{:032x}", target.0))),
            ("as_of", s(as_of.to_string())),
            ("max_depth", Json::Int(max_depth as i128)),
            ("stake", s(&ratio)),
            ("known_at", Json::Int(i128::from(rea.known_at.0))),
        ],
        &format!(
            "{owner_raw} holds {ratio} of {target_raw} on {as_of} (OWNS chains of up to {max_depth} edges)"
        ),
    );
    Ok(())
}

fn party_list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "party list takes no argument",
            "fa party list --json",
        ));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| admit_read(book, who, &cap))?;
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
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| admit_read(book, who, &cap))?;
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

/// An optional `YYYY-MM-DD` field of an add's JSON object.
fn optional_date(doc: &Json, field: &str, example: &str) -> Result<Option<DateDay>, Fail> {
    match doc.get(field) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Str(text)) => DateDay::parse(text)
            .map(Some)
            .map_err(|e| usage(format!("`{field}`: {e}"), example)),
        Some(_) => Err(usage(format!("`{field}` must be YYYY-MM-DD"), example)),
    }
}

/// A legal entity (plan §4.1, §4.5): a reporting entity with its
/// jurisdiction, functional unit and life span. A code the book declared at
/// genesis (`fa book create --entity`) is lifted to this full specification
/// under its declared name; any other code is a new legal entity.
fn entity_add(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const FIX: &str = "{\"code\": \"ACME-DE\", \"name\": \"Acme GmbH\", \"jurisdiction\": \"DE\", \"functional_unit\": \"USD\", \"formed\": \"2019-04-01\", \"external_ids\": [{\"system\": \"lei\", \"id\": \"5299001ABCDEF\"}]}";
    let doc = read_object(
        ctx,
        args,
        &[
            "code",
            "name",
            "jurisdiction",
            "functional_unit",
            "formed",
            "dissolved",
            "external_ids",
        ],
        FIX,
    )?;
    let code = required(&doc, "code", FIX)?.to_string();
    let name = required(&doc, "name", FIX)?.to_string();
    let jurisdiction = required(&doc, "jurisdiction", FIX)?.to_string();
    let unit_code = required(&doc, "functional_unit", FIX)?;
    let formed = optional_date(&doc, "formed", FIX)?;
    let dissolved = optional_date(&doc, "dissolved", FIX)?;
    let ids = requested_ids(&doc)?;
    let key = args
        .flag("--key")
        .map_or_else(|| format!("entity:{code}"), str::to_string);
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &capability)??;
        Ok(())
    })?;
    let functional_unit = book.context().units.lookup(unit_code).ok_or_else(|| {
        usage(
            format!("unknown unit `{unit_code}`"),
            "functional_unit: a registered unit code such as USD",
        )
    })?;
    let spec = LegalEntityFullSpec {
        code: code.clone(),
        name,
        jurisdiction,
        functional_unit,
        formed,
        dissolved,
        external_ids: sealed_ids(&book, &ids)?,
    };
    let date = date_flag(args, DateDay(0))?;
    let recorded = book.create_legal_entity(&spec, who, date, key.as_bytes(), &capability)??;
    emit_recorded(&ctx.out, &book, "legal_entity", &code, &recorded)
}

fn entity_list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "entity list takes no argument",
            "fa entity list --json",
        ));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| admit_read(book, who, &cap))?;
    let rea = book.rea_snapshot(None)?;
    let units = &book.context().units;
    let mut entities: Vec<_> = rea.legal_entities.values().collect();
    entities.sort_by(|a, b| a.code.cmp(&b.code));
    let rows: Vec<Json> = entities
        .iter()
        .map(|e| {
            obj(vec![
                ("code", s(&e.code)),
                ("name", s(&e.name)),
                ("jurisdiction", s(&e.jurisdiction)),
                (
                    "functional_unit",
                    units
                        .get(e.functional_unit)
                        .map_or(Json::Null, |u| s(u.code.as_str())),
                ),
                ("formed", e.formed.map_or(Json::Null, |d| s(d.to_string()))),
                (
                    "dissolved",
                    e.dissolved.map_or(Json::Null, |d| s(d.to_string())),
                ),
                ("external_ids", Json::Int(e.external_ids.len() as i128)),
                ("vid", s(format!("{:032x}", e.vid.0))),
                ("created_at", Json::Int(i128::from(e.created_at.0))),
            ])
        })
        .collect();
    let human: Vec<String> = entities
        .iter()
        .map(|e| format!("{:<16} {:<8} {}", e.code, e.jurisdiction, e.name))
        .collect();
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "legal_entities",
        vec![
            ("known_at", Json::Int(i128::from(rea.known_at.0))),
            ("entities", Json::Arr(rows)),
        ],
        &human.join("\n"),
    );
    Ok(())
}

/// `fa party identifiers <code> --identifier <name>=<value>... --key <change>`
/// (plan §4.5, §14.4): replace a party's identifier set (bank routing and
/// account numbers, tax ids). Changing a vendor's bank details is the
/// business-email-compromise vector, so the change is named by the caller's
/// --key (no default: one derived from the values would leak them, one
/// derived from the code would collide across changes), every value is
/// sealed with the book's key and never echoed, and the change needs
/// schema_change authority. `--clear` removes every identifier.
fn party_identifiers(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const FIX: &str = "fa party identifiers <party code> --identifier <name>=<value>... --key <change-id>   (or --clear --key <change-id>)";
    let [_, _, target] = args.positional.as_slice() else {
        return Err(usage("party identifiers needs one party code", FIX));
    };
    let key = match args.flag_all("--key").as_slice() {
        [key] if !key.is_empty() => *key,
        _ => {
            return Err(usage(
                "party identifiers needs exactly one --key naming the change (for example chg-2026-03-17)",
                FIX,
            ));
        }
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    for raw in args.flag_all("--identifier") {
        let Some((name, value)) = raw
            .split_once('=')
            .filter(|(name, value)| !name.is_empty() && !value.is_empty())
        else {
            // Never echo the value: it may be a bank account number.
            return Err(usage("an --identifier is not <name>=<value>", FIX));
        };
        pairs.push((name.to_string(), value.to_string()));
    }
    if pairs.is_empty() != args.switch("--clear") {
        return Err(usage(
            "give the new identifier set with --identifier <name>=<value>..., or --clear to remove every identifier",
            FIX,
        ));
    }
    pairs.sort();
    if let Some(pair) = pairs.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(usage(
            format!("identifier `{}` is given twice", pair[0].0),
            FIX,
        ));
    }
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &capability)??;
        Ok(())
    })?;
    let rea = book.rea_snapshot(None)?;
    let Some(party) = rea.parties.values().find(|p| p.code == *target) else {
        return Err(usage(
            format!("no party `{target}` in this book"),
            "fa party list names them",
        ));
    };
    let party_vid = party.vid;
    let mut identifiers = Vec::with_capacity(pairs.len());
    for (name, value) in &pairs {
        identifiers.push((name.clone(), book.seal_text(value)?));
    }
    let update = fa_model::PartyIdentifierUpdate {
        party_vid,
        identifiers,
    };
    let date = date_flag(args, DateDay(0))?;
    let recorded =
        book.update_party_identifiers(&update, who, date, key.as_bytes(), &capability)??;
    emit_recorded(&ctx.out, &book, "party_identifiers", target, &recorded)
}

/// Bind an external system's identifier to a party, legal entity or
/// instrument (plan §4.5): the id another system knows it by, sealed with
/// the book's key. One (system, id) names one vertex; the default key names
/// the target and system, never the sealed id. The target is a code, refused
/// when it names more than one kind, or a 32-hex vertex id.
fn party_bind(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const FIX: &str =
        "fa party bind <party|entity|instrument code> --external-id <system>:<id> [--key K]";
    let [_, _, target] = args.positional.as_slice() else {
        return Err(usage("party bind needs one target code", FIX));
    };
    let raw = match args.flag_all("--external-id").as_slice() {
        [one] => *one,
        _ => return Err(usage("party bind takes exactly one --external-id", FIX)),
    };
    let (system, id) = raw
        .split_once(':')
        .filter(|(system, id)| !system.is_empty() && !id.is_empty())
        // The id is sealed once recorded; a malformed one is not echoed.
        .ok_or_else(|| usage("--external-id is not <system>:<id>", FIX))?;
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &capability)??;
        Ok(())
    })?;
    let rea = book.rea_snapshot(None)?;
    // Codes are unique within a kind, not across kinds: a code that names
    // more than one target is refused, and a 32-hex vertex id names one.
    let wanted = u128::from_str_radix(target, 16)
        .ok()
        .filter(|_| target.len() == 32)
        .map(VId);
    let named = |code: &str, vid: VId| wanted.map_or(code == *target, |w| w == vid);
    let found: Vec<(&str, VId)> = rea
        .parties
        .values()
        .filter(|p| named(&p.code, p.vid))
        .map(|p| ("party", p.vid))
        .chain(
            rea.legal_entities
                .values()
                .filter(|e| named(&e.code, e.vid))
                .map(|e| ("legal entity", e.vid)),
        )
        .chain(
            rea.instruments
                .values()
                .filter(|i| named(&i.code, i.vid))
                .map(|i| ("instrument", i.vid)),
        )
        .collect();
    let target_vid = match found.as_slice() {
        [] => {
            return Err(usage(
                format!("no party, legal entity or instrument `{target}` in this book"),
                "fa party list, fa entity list or fa instrument list names them",
            ));
        }
        [(_, vid)] => *vid,
        many => {
            let kinds = many
                .iter()
                .map(|(kind, vid)| format!("{kind} {:032x}", vid.0))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(usage(
                format!("`{target}` names more than one target: {kinds}"),
                format!("fa party bind <vertex id> --external-id {system}:<id>"),
            ));
        }
    };
    let key = args
        .flag("--key")
        .map_or_else(|| format!("bind:{target}:{system}"), str::to_string);
    let binding = ExternalIdBinding {
        target_vid,
        external_id: ExternalId {
            system: system.to_string(),
            id: book.seal_text(id)?,
        },
    };
    let date = date_flag(args, DateDay(0))?;
    let recorded = book.bind_external_id(&binding, who, date, key.as_bytes(), &capability)??;
    emit_recorded(&ctx.out, &book, "external_id", target, &recorded)
}
