//! The plan Appendix D refusal object, rendered from a kernel [`Refusal`]
//! into the `error` event's `refusal` field (fa-mcp carries the same object
//! in a tool error's `data.refusal`):
//!
//! `{id, code, exit, what_failed, where, why, fix: {text, command, argv,
//! or_field_change, rerun_with}, alternatives, docs}`
//!
//! - `id` (Appendix D's `refusal_id`; renamed so a text search for the
//!   event's flat `refusal_id`, which stays the catalog code, never lands
//!   in this object) names this instance: the catalog code, `:`, and 16 hex
//!   digits of a domain digest over the code, message, structured `where`
//!   and the coordinate (book, known_at). It is a citation, not a lookup
//!   key: `fa explain refusal` accepts it and expands its code.
//! - `where` is the refusing site's structured location, an empty object
//!   when the site gives none.
//! - `why` is `{law}`, `{policy}` or `{matrix: {state, class}}` when the site
//!   set it, else `{law}` from the first `FA-INV-nn[.clause]` the citation
//!   names, else `{cite}` (the prose).
//! - `fix.command` is the first `fa …` command the instance fix names that
//!   parses against `verbs.toml` — a known verb or alias, subcommand and
//!   flags, no placeholder — with `argv` its tokens after `fa`; both null
//!   when the fix names none, and `fix.text` (the prose) is the next step.
//!   Parsing is not success: the command may still need values the book
//!   decides.
//! - `fix.rerun_with` are the arguments that, added to the refused command,
//!   make it admissible (`--yes`, `--grant <op>`); null when none do, and
//!   always null in a launch-bound session, which cannot add them.
//! - `alternatives` are the other such commands the instance fix and its
//!   catalog row's fix name.
//! - `docs` is the command that expands the code from the catalog.

use fa_journal::{Locus, Refusal, Why};

use crate::args;
use crate::json::Json;
use crate::verbs::Registry;

/// The coordinate a refusal instance was issued at.
pub(crate) struct Issued<'a> {
    pub book: Option<&'a str>,
    pub known_at: Option<u64>,
}

/// The Appendix D object for `r`.
pub(crate) fn render(reg: &Registry, r: &Refusal, issued: &Issued<'_>) -> Json {
    let place = Json::Obj(
        r.location()
            .iter()
            .map(|(k, v)| {
                let value = match v {
                    Locus::Text(t) => Json::Str(t.clone()),
                    Locus::Index(i) => Json::Int(i128::from(*i)),
                };
                ((*k).to_string(), value)
            })
            .collect(),
    );
    let mut commands = commands_in(reg, &r.fix);
    if let Ok(catalog) = fa_registry::refusal_catalog::RefusalCatalog::embedded()
        && let Some(row) = catalog.by_code(r.code)
    {
        for c in commands_in(reg, &row.fix) {
            if !commands.contains(&c) {
                commands.push(c);
            }
        }
    }
    let mut commands = commands.into_iter();
    let first = commands.next();
    let field_change = r.field_change().map_or(Json::Null, |c| {
        Json::Obj(vec![
            ("field".into(), Json::Str(c.field.clone())),
            (
                "one_of".into(),
                Json::Arr(c.one_of.iter().cloned().map(Json::Str).collect()),
            ),
        ])
    });
    Json::Obj(vec![
        ("id".into(), Json::Str(instance_id(r, issued))),
        ("code".into(), Json::Str(r.code.to_string())),
        ("exit".into(), Json::Int(i128::from(r.exit))),
        ("what_failed".into(), Json::Str(r.message.clone())),
        ("where".into(), place),
        ("why".into(), why(r)),
        (
            "fix".into(),
            Json::Obj(vec![
                ("text".into(), Json::Str(r.fix.clone())),
                (
                    "command".into(),
                    first
                        .as_ref()
                        .map_or(Json::Null, |argv| Json::Str(command_line(argv))),
                ),
                (
                    "argv".into(),
                    first.map_or(Json::Null, |argv| {
                        Json::Arr(argv.into_iter().map(Json::Str).collect())
                    }),
                ),
                ("or_field_change".into(), field_change),
                (
                    "rerun_with".into(),
                    if r.rerun_args().is_empty() {
                        Json::Null
                    } else {
                        Json::Arr(r.rerun_args().iter().cloned().map(Json::Str).collect())
                    },
                ),
            ]),
        ),
        (
            "alternatives".into(),
            Json::Arr(
                commands
                    .map(|argv| Json::Str(command_line(&argv)))
                    .collect(),
            ),
        ),
        (
            "docs".into(),
            Json::Str(format!("fa explain refusal {}", r.code)),
        ),
    ])
}

/// `FA-REF-nnn:` and 16 hex digits binding the instance to its coordinate.
fn instance_id(r: &Refusal, issued: &Issued<'_>) -> String {
    let mut place = Vec::new();
    for (k, v) in r.location() {
        place.extend_from_slice(k.as_bytes());
        place.push(0);
        match v {
            Locus::Text(t) => place.extend_from_slice(t.as_bytes()),
            Locus::Index(i) => place.extend_from_slice(&i.to_le_bytes()),
        }
        place.push(0);
    }
    let known_at = issued.known_at.map(u64::to_le_bytes).unwrap_or_default();
    let digest = fa_model::domain_digest(
        b"fa:refusal-instance:v1",
        &[
            r.code.as_bytes(),
            r.message.as_bytes(),
            &place,
            issued.book.unwrap_or_default().as_bytes(),
            &known_at,
        ],
    );
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("{}:{hex}", r.code)
}

/// Whether `id` has an instance id's form: a code, `:`, 16 lowercase hex.
pub(crate) fn is_instance_id(id: &str) -> bool {
    id.split_once(':').is_some_and(|(code, hex)| {
        code.starts_with("FA-REF-")
            && hex.len() == 16
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The catalog code an instance id (or a bare code) names.
pub(crate) fn code_of(refusal_id: &str) -> &str {
    refusal_id
        .split_once(':')
        .map_or(refusal_id, |(code, _)| code)
}

fn why(r: &Refusal) -> Json {
    let one = |k: &str, v: Json| Json::Obj(vec![(k.to_string(), v)]);
    match r.why() {
        Some(Why::Law(law)) => one("law", Json::Str(law.clone())),
        Some(Why::Policy(policy)) => one("policy", Json::Str(policy.clone())),
        Some(Why::Matrix { state, class }) => one(
            "matrix",
            Json::Obj(vec![
                ("state".into(), Json::Str(state.clone())),
                ("class".into(), Json::Str(class.clone())),
            ]),
        ),
        None => match invariant_in(&r.cite) {
            Some(law) => one("law", Json::Str(law)),
            None => one("cite", Json::Str(r.cite.clone())),
        },
    }
}

/// The first `FA-INV-nn` (with its `.clause`, when one follows) in `cite`.
fn invariant_in(cite: &str) -> Option<String> {
    let at = cite.find("FA-INV-")?;
    let rest = &cite[at..];
    let digits = rest["FA-INV-".len()..]
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    if digits == 0 {
        return None;
    }
    let mut end = "FA-INV-".len() + digits;
    if rest[end..].starts_with('.') {
        let clause = rest[end + 1..]
            .bytes()
            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            .count();
        if clause > 0 {
            end += 1 + clause;
        }
    }
    Some(rest[..end].to_string())
}

/// Every `fa …` command in `text` that parses against the registry, as argv
/// after `fa`, in order, without repeats: backticked spans first, then bare
/// `fa <verb> …` runs, which end at punctuation or the first plain word
/// that is not part of the command.
pub(crate) fn commands_in(reg: &Registry, text: &str) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut push = |argv: Option<Vec<String>>| {
        if let Some(argv) = argv
            && !out.contains(&argv)
        {
            out.push(argv);
        }
    };
    let mut prose = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('`') {
        prose.push_str(&rest[..start]);
        prose.push(' ');
        let after = &rest[start + 1..];
        let Some(end) = after.find('`') else {
            rest = after;
            break;
        };
        push(parse(reg, &after[..end]));
        rest = &after[end + 1..];
    }
    prose.push_str(rest);
    let words: Vec<&str> = prose
        .split_whitespace()
        .map(|w| w.trim_start_matches(['(', '"']))
        .collect();
    for (i, w) in words.iter().enumerate() {
        if *w != "fa" {
            continue;
        }
        let mut line = vec!["fa".to_string()];
        for w in &words[i + 1..] {
            let ends = w.ends_with([',', ';', ':', ')', '.']);
            let word = w.trim_end_matches([',', ';', ':', ')', '.']);
            if word.is_empty() || (!word.starts_with('-') && line.len() > 2 && is_prose(word)) {
                break;
            }
            line.push(word.to_string());
            if ends {
                break;
            }
        }
        push(parse(reg, &line.join(" ")));
    }
    out
}

/// A plain English word that ends a bare command.
fn is_prose(word: &str) -> bool {
    matches!(
        word,
        "to" | "or"
            | "and"
            | "then"
            | "for"
            | "when"
            | "if"
            | "so"
            | "the"
            | "a"
            | "an"
            | "is"
            | "are"
            | "lists"
            | "shows"
            | "prints"
            | "first"
            | "instead"
    )
}

/// `line` as argv after `fa` when it is one parseable `fa` command with no
/// placeholder.
fn parse(reg: &Registry, line: &str) -> Option<Vec<String>> {
    let tokens = split(line);
    let (first, rest) = tokens.split_first()?;
    if first != "fa" || rest.is_empty() || tokens.iter().any(|t| is_placeholder(t)) {
        return None;
    }
    let parsed = args::parse(rest, &reg.value_flags(), &reg.switches()).ok()?;
    let word = parsed.positional.first()?;
    let mut positional: Vec<String> = match reg.alias(word) {
        Some(alias) => alias.expands.clone(),
        None => vec![word.clone()],
    };
    positional.extend(parsed.positional.iter().skip(1).cloned());
    let verb = reg.verb(&positional[0])?;
    if !verb.subcommands.is_empty() {
        match positional.get(1) {
            Some(sub) if verb.subcommands.contains(sub) => {}
            None if verb.default_subcommand.is_some() => {}
            _ => return None,
        }
    }
    let global = |f: &String| reg.global.flags.contains(f) || reg.global.switches.contains(f);
    if !parsed
        .flags
        .keys()
        .chain(&parsed.switches)
        .all(|f| global(f) || verb.accepts(f))
    {
        return None;
    }
    Some(rest.to_vec())
}

/// A template slot (`<dir>`, `{account}`, `…`) rather than a value.
fn is_placeholder(token: &str) -> bool {
    token.contains(['<', '>', '{', '}', '…', '[', ']', '|']) || token.contains("...")
}

/// Whitespace split honoring single and double quotes.
fn split(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                in_word = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    out.push(core::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// argv as one shell line, quoting tokens that need it.
fn command_line(argv: &[String]) -> String {
    let mut line = String::from("fa");
    for a in argv {
        line.push(' ');
        if !a.is_empty()
            && a.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@,+".contains(&b))
        {
            line.push_str(a);
        } else {
            line.push('\'');
            line.push_str(&a.replace('\'', r"'\''"));
            line.push('\'');
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> &'static Registry {
        crate::verbs::registry().expect("verbs.toml")
    }

    #[test]
    fn commands_are_found_in_backticks_and_bare_prose() {
        let found = commands_in(
            reg(),
            "fa chart list --json to find the account, or fa chart import to add it",
        );
        assert_eq!(
            found,
            vec![
                vec!["chart".to_string(), "list".into(), "--json".into()],
                vec!["chart".to_string(), "import".into()],
            ]
        );
        assert_eq!(
            commands_in(
                reg(),
                "a leaf under `100` (fa chart list --json lists them all)"
            ),
            vec![vec!["chart".to_string(), "list".into(), "--json".into()]]
        );
        let found = commands_in(
            reg(),
            "keep the date; `fa period list --json` shows each period's state",
        );
        assert_eq!(
            found,
            vec![vec!["period".to_string(), "list".into(), "--json".into()]]
        );
    }

    #[test]
    fn placeholders_unknown_verbs_and_foreign_flags_are_not_commands() {
        for text in [
            "`fa period create --fiscal-year <FY>`",
            "`fa consolidate --all`",
            "`fa tb --not-a-flag`",
            "`fa chart frobnicate`",
            "`fa post --intent {file}`",
        ] {
            assert!(commands_in(reg(), text).is_empty(), "{text}");
        }
    }

    #[test]
    fn the_cited_invariant_clause_is_the_law() {
        assert_eq!(
            invariant_in("FA-INV-01.account-effective (plan §4.3)").as_deref(),
            Some("FA-INV-01.account-effective")
        );
        assert_eq!(
            invariant_in("FA-INV-01 per-unit balance law").as_deref(),
            Some("FA-INV-01")
        );
        assert_eq!(invariant_in("plan §4.3"), None);
    }

    /// Every catalog row, raised with its own cite and fix template, renders
    /// a complete object: the fields in order, an instance id carrying its
    /// code, a non-empty `why`, and a `fix.command` and alternatives that
    /// re-parse. Each object is logged.
    #[test]
    fn every_catalog_row_renders_a_complete_appendix_d_object() {
        let catalog =
            fa_registry::refusal_catalog::RefusalCatalog::embedded().expect("refusal_catalog.toml");
        let issued = Issued {
            book: Some("00"),
            known_at: Some(1),
        };
        let mut with_command = 0;
        for row in &catalog.rows {
            let code: &'static str = Box::leak(row.code.clone().into_boxed_str());
            let r = Refusal::new(
                code,
                row.exit,
                format!("{} refused", row.name),
                row.cite.clone(),
                row.fix.clone(),
            );
            let object = render(reg(), &r, &issued);
            println!("{}", object.render());
            let Json::Obj(fields) = &object else {
                panic!("{code}: not an object");
            };
            let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(
                keys,
                [
                    "id",
                    "code",
                    "exit",
                    "what_failed",
                    "where",
                    "why",
                    "fix",
                    "alternatives",
                    "docs"
                ],
                "{code}"
            );
            let id = object.get("id").and_then(Json::as_str).expect("id");
            assert!(is_instance_id(id) && code_of(id) == code, "{code}: {id}");
            let Some(Json::Obj(why)) = object.get("why") else {
                panic!("{code}: why is not an object");
            };
            assert_eq!(why.len(), 1, "{code}");
            assert!(
                why[0].1.as_str().is_none_or(|v| !v.is_empty()),
                "{code}: empty why"
            );
            let fix = object.get("fix").expect("fix");
            if let Some(command) = fix.get("command").and_then(Json::as_str) {
                with_command += 1;
                assert!(parse(reg(), command).is_some(), "{code}: {command}");
            }
            for alternative in object
                .get("alternatives")
                .and_then(Json::as_arr)
                .expect("alternatives")
            {
                let alternative = alternative.as_str().expect("string");
                assert!(parse(reg(), alternative).is_some(), "{code}: {alternative}");
            }
        }
        println!(
            "{} catalog rows rendered; {with_command} name a parseable command",
            catalog.rows.len()
        );
        assert!(with_command > 0);
    }

    #[test]
    fn the_instance_id_carries_its_code_and_binds_the_coordinate() {
        let r = Refusal::new("FA-REF-002", 3, "leg 0 posts to `1000`", "plan §4.3", "x")
            .at("leg", 0_usize);
        let a = instance_id(
            &r,
            &Issued {
                book: Some("ab"),
                known_at: Some(7),
            },
        );
        let b = instance_id(
            &r,
            &Issued {
                book: Some("ab"),
                known_at: Some(8),
            },
        );
        assert!(a.starts_with("FA-REF-002:") && a.len() == "FA-REF-002:".len() + 16);
        assert_ne!(a, b);
        assert_eq!(code_of(&a), "FA-REF-002");
        assert_eq!(code_of("FA-REF-002"), "FA-REF-002");
        assert!(is_instance_id(&a));
        assert!(!is_instance_id("FA-REF-002:zz"));
        assert!(!is_instance_id("FA-REF-002"));
    }
}
