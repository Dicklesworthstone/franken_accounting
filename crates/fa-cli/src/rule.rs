//! `fa rule check|eval` (plan §10.3, §10.5, bead fa-c34). A Canon posting
//! rule is a text file. `check` compiles it against the book's units:
//! names, unit types, registered rounding laws and dimensions, and the
//! per-unit balance proof; it reports the IR's content address and the
//! rule's dependency set. `eval` runs a checked rule over one recorded REA
//! event and reports the legs it derives. Both only read: nothing is
//! journaled and nothing is posted.

use fa::rule::{
    CompiledRule, Derivation, EvalError, InputType, InputValue, Inputs, compile_rule,
    evaluation_refusal,
};
use fa_money::{Amount, Side};
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{Ctx, Fail, find_event, hex, known_at_read_flag, usage};
use crate::json::{Json, obj, s};

const CHECK: &str = "fa rule check <rule-file|->";
const EVAL: &str = "fa rule eval <rule-file|-> --event <code|vid> [--input <name>=<value>]... [--as-known-at HEAD|<seq>]";

pub(crate) fn rule_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("check") => check(ctx, args),
        Some("eval") => eval(ctx, args),
        _ => Err(usage(
            "rule has the subcommands check and eval",
            format!("{CHECK} | {EVAL}"),
        )),
    }
}

fn source<'a>(args: &'a Args, line: &str) -> Result<&'a str, Fail> {
    match args.positional.as_slice() {
        [_, _, file] => Ok(file),
        _ => Err(usage("name one rule file, or `-` for stdin", line)),
    }
}

fn strings<'a>(items: impl IntoIterator<Item = &'a String>) -> Json {
    Json::Arr(items.into_iter().map(s).collect())
}

fn rule_fields(rule: &CompiledRule) -> Vec<(&'static str, Json)> {
    vec![
        ("rule", s(rule.name())),
        ("version", Json::Int(i128::from(rule.version()))),
        ("event_kind", s(rule.event().name())),
        ("ir_digest", s(hex(&rule.ir_digest()))),
    ]
}

/// `fa rule check <rule-file|->`.
fn check(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let path = source(args, CHECK)?;
    let text = ctx.files.read_text(path)?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let rule = compile_rule(book.context(), &text).map_err(Fail::Refusal)?;
    let deps = rule.dependencies();
    let inputs: Vec<String> = rule
        .inputs()
        .iter()
        .map(|input| match &input.ty {
            InputType::Date => format!("{}: date", input.name),
            InputType::Amount(unit) => format!(
                "{}: amount {}",
                input.name,
                book.context()
                    .units
                    .get(*unit)
                    .map_or_else(|| format!("#{}", unit.0), fa_money::Unit::spelling)
            ),
        })
        .collect();
    let resources: Vec<String> = deps
        .resources
        .iter()
        .map(|(label, unit)| format!("{label}:{unit}"))
        .collect();
    let tags: Vec<String> = deps
        .dimensions
        .iter()
        .map(|(dimension, code)| format!("{dimension}={code}"))
        .collect();
    let mut fields = rule_fields(&rule);
    fields.extend([
        (
            "ir_bytes",
            Json::Int(i128::try_from(rule.ir().len()).unwrap_or(i128::MAX)),
        ),
        ("inputs", strings(&inputs)),
        ("accounts", strings(&deps.accounts)),
        ("units", strings(&deps.units)),
        ("laws", strings(&deps.laws)),
        ("resources", strings(&resources)),
        ("dimensions", strings(&tags)),
    ]);
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "rule_checked",
        fields,
        &format!(
            "rule {} v{} for {} events balances in every unit; IR {}\nposts to {}",
            rule.name(),
            rule.version(),
            rule.event().name(),
            hex(&rule.ir_digest()),
            deps.accounts
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    Ok(())
}

/// Parse `--input <name>=<value>` against the rule's declared inputs.
fn inputs(
    rule: &CompiledRule,
    args: &Args,
    units: &fa_money::UnitRegistry,
) -> Result<Inputs, Fail> {
    let mut out = Inputs::new();
    for raw in args.flag_all("--input") {
        let Some((name, value)) = raw.split_once('=') else {
            return Err(usage(
                format!("--input `{raw}` is not <name>=<value>"),
                "--input as_of=2026-03-31 or --input fee=\"10.00 USD\"",
            ));
        };
        let Some(decl) = rule.inputs().iter().find(|decl| decl.name == name) else {
            let declared: Vec<&str> = rule.inputs().iter().map(|d| d.name.as_str()).collect();
            return Err(usage(
                format!(
                    "the rule declares no input `{name}`; it declares [{}]",
                    declared.join(", ")
                ),
                EVAL,
            ));
        };
        let parsed = match &decl.ty {
            InputType::Date => DateDay::parse(value).map(InputValue::Date).map_err(|e| {
                usage(
                    format!("--input {name}: `{value}` is not a date ({e:?})"),
                    format!("--input {name}=YYYY-MM-DD"),
                )
            })?,
            InputType::Amount(unit) => {
                let amount = Amount::parse(value, units).map_err(|e| {
                    usage(
                        format!("--input {name}: `{value}`: {e}"),
                        format!("--input {name}=\"12.50 <UNIT>\""),
                    )
                })?;
                if amount.unit != *unit {
                    return Err(usage(
                        format!("--input {name} is declared in another unit than `{value}`"),
                        "fa rule check <file> lists each input's unit",
                    ));
                }
                InputValue::Amount(amount)
            }
        };
        out.set(name, parsed);
    }
    Ok(out)
}

fn leg_json(leg: &fa::rule::DerivedLeg, units: &fa_money::UnitRegistry) -> Json {
    obj(vec![
        (
            "side",
            s(match leg.side {
                Side::Debit => "debit",
                Side::Credit => "credit",
            }),
        ),
        ("account", s(&leg.account)),
        ("amount", s(leg.amount.render(units))),
        (
            "dimensions",
            Json::Arr(
                leg.dims
                    .iter()
                    .map(|(dimension, code)| s(format!("{dimension}={code}")))
                    .collect(),
            ),
        ),
    ])
}

/// `fa rule eval <rule-file|-> --event <code|vid> [--input <name>=<value>]...`.
fn eval(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let path = source(args, EVAL)?;
    let Some(target) = args.flag("--event") else {
        return Err(usage("rule eval needs --event", EVAL));
    };
    let text = ctx.files.read_text(path)?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let mut selected = None;
    let book = ctx.books.open_admitted(args, |book| {
        let scope = book.read_scope(who, &cap)??;
        let (known_at, _) = known_at_read_flag(args, book, &ctx.out, &cap)?;
        let seq = scope.admit_whole_book(known_at)??;
        selected = Some(book.rea_snapshot(Some(seq))?);
        Ok(())
    })?;
    let rea = selected.ok_or_else(|| Fail::Internal("event snapshot is missing".into()))?;
    let rule = compile_rule(book.context(), &text).map_err(Fail::Refusal)?;
    let units = &book.context().units;
    let given = inputs(&rule, args, units)?;
    let event = find_event(&rea, book.context().book_id, target).ok_or_else(|| {
        usage(
            format!("no event `{target}` in this book at {}", rea.known_at.0),
            "fa event list --book <dir> --json",
        )
    })?;
    let derived: Derivation =
        fa::rule::evaluate(&rule, &event.spec, &given).map_err(|error| match &error {
            EvalError::MissingInput { name } => usage(
                format!("the rule declares input `{name}`; supply it"),
                format!("--input {name}=<value>"),
            ),
            _ => Fail::Refusal(evaluation_refusal(&rule, &event.spec.code, &error)),
        })?;
    ctx.out.known_at(rea.known_at);
    let mut human = vec![format!(
        "rule {} v{} over event {} derives {} legs effective {} (nothing is posted)",
        rule.name(),
        rule.version(),
        event.spec.code,
        derived.legs.len(),
        derived.effective.render()
    )];
    human.extend(derived.legs.iter().map(|leg| {
        format!(
            "{:<6} {:<12} {:>20} {}",
            match leg.side {
                Side::Debit => "debit",
                Side::Credit => "credit",
            },
            leg.account,
            leg.amount.render(units),
            leg.dims
                .iter()
                .map(|(dimension, code)| format!("{dimension}={code}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }));
    let mut fields = rule_fields(&rule);
    fields.extend([
        ("event_code", s(&event.spec.code)),
        ("event_vid", s(format!("{:032x}", event.vid.0))),
        ("event_digest", s(hex(&derived.event_digest))),
        ("inputs_digest", s(hex(&derived.inputs_digest))),
        ("effective", s(derived.effective.render())),
        (
            "legs",
            Json::Arr(
                derived
                    .legs
                    .iter()
                    .map(|leg| leg_json(leg, units))
                    .collect(),
            ),
        ),
    ]);
    ctx.out.event("rule_evaluated", fields, &human.join("\n"));
    Ok(())
}
