//! `fa rule check|propose|list|show|activate|eval|derive` (plan §10.3,
//! §10.5, §10.6, bead fa-c34). A Canon posting rule is a text file. `check` compiles it against
//! the book's units: names, unit types, registered rounding laws and
//! dimensions, and the per-unit balance proof. It reports the IR's content
//! address and the rule's dependency set. `propose` journals the version
//! under `rule_change`; `list` and `show` read the versions the book holds;
//! `eval` runs a rule, from a file or a journaled version, over one recorded
//! REA event and reports the legs it derives. `activate` binds a version to
//! its name from a date under dual control, and `derive` posts what the
//! version in force derives from an event; the kernel re-derives it in the
//! commit.

use fa::rule::{
    CompiledRule, Derivation, EvalError, InputType, InputValue, Inputs,
    RULE_ACTIVATION_PLAN_DOMAIN, RuleActivationPlan, RuleNameRow, RuleVersionRow, compile_rule,
    evaluation_refusal,
};
use fa_money::{Amount, Side};
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, find_event, hex, known_at_read_flag, parse_vid, read_plan_bytes, usage,
};
use crate::json::{Json, obj, s};

const CHECK: &str = "fa rule check <rule-file|->";
const PROPOSE: &str = "fa rule propose <rule-file|-> [--key K]";
const LIST: &str = "fa rule list [--as-known-at HEAD|<seq>]";
const SHOW: &str = "fa rule show <ir_digest> [--as-known-at HEAD|<seq>]";
const ACTIVATE: &str = "fa rule activate <ir_digest> --from YYYY-MM-DD [--key K] --dry-run";
const COMMIT: &str = "fa rule activate --plan <file|-> --approval <vid> --approval <vid>";
const DERIVE: &str =
    "fa rule derive [--rule <ir_digest> [--input <name>=<value>]... [--key K]] --event <code|vid>";
const EVAL: &str = "fa rule eval (<rule-file|-> | --rule <ir_digest>) --event <code|vid> [--input <name>=<value>]... [--as-known-at HEAD|<seq>]";

pub(crate) fn rule_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("check") => check(ctx, args),
        Some("propose") => propose(ctx, args),
        Some("list") => list(ctx, args),
        Some("show") => show(ctx, args),
        Some("activate") => activate(ctx, args),
        Some("eval") => eval(ctx, args),
        Some("derive") => derive(ctx, args),
        _ => Err(usage(
            "rule has the subcommands check, propose, list, show, activate, eval and derive",
            format!("{CHECK} | {PROPOSE} | {LIST} | {SHOW} | {ACTIVATE} | {EVAL} | {DERIVE}"),
        )),
    }
}

fn source<'a>(args: &'a Args, line: &str) -> Result<&'a str, Fail> {
    match args.positional.as_slice() {
        [_, _, file] => Ok(file),
        _ => Err(usage("name one rule file, or `-` for stdin", line)),
    }
}

fn digest_arg(text: &str, line: &str) -> Result<[u8; 32], Fail> {
    let bad = || {
        usage(
            format!("`{text}` is not a rule version's 64-hex ir_digest"),
            format!("{line}   (fa rule list names each version's ir_digest)"),
        )
    };
    if text.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = text
            .get(i * 2..i * 2 + 2)
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or_else(bad)?;
    }
    Ok(out)
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

/// The inputs and dependency set `check` and `show` report.
fn dependency_fields(
    rule: &CompiledRule,
    units: &fa_money::UnitRegistry,
) -> Vec<(&'static str, Json)> {
    let deps = rule.dependencies();
    let inputs: Vec<String> = rule
        .inputs()
        .iter()
        .map(|input| match &input.ty {
            InputType::Date => format!("{}: date", input.name),
            InputType::Amount(unit) => format!(
                "{}: amount {}",
                input.name,
                units
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
    vec![
        ("inputs", strings(&inputs)),
        ("accounts", strings(&deps.accounts)),
        ("units", strings(&deps.units)),
        ("laws", strings(&deps.laws)),
        ("resources", strings(&resources)),
        ("dimensions", strings(&tags)),
    ]
}

fn accounts_line(rule: &CompiledRule) -> String {
    rule.dependencies()
        .accounts
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
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
    let mut fields = rule_fields(&rule);
    fields.push((
        "ir_bytes",
        Json::Int(i128::try_from(rule.ir().len()).unwrap_or(i128::MAX)),
    ));
    fields.extend(dependency_fields(&rule, &book.context().units));
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
            accounts_line(&rule)
        ),
    );
    Ok(())
}

/// `fa rule propose <rule-file|-> [--key K]`.
fn propose(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let path = source(args, PROPOSE)?;
    let text = ctx.files.read_text(path)?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["rule_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rule_change(who, &cap)??;
        Ok(())
    })?;
    // The default key is the source's own digest, so proposing the same text
    // again is a retry.
    let key = args.flag("--key").map_or_else(
        || {
            format!(
                "rule-propose:{}",
                hex(&fa_model::domain_digest(
                    b"fa:rule-source:v1",
                    &[text.as_bytes()]
                ))
            )
        },
        str::to_string,
    );
    let recorded = book.propose_rule_version(&text, who, key.as_bytes(), &cap)??;
    ctx.out.at_book(&book)?;
    let version = &recorded.version;
    let mut fields = rule_fields(&version.rule);
    fields.extend([
        ("rule_version_vid", s(format!("{:032x}", version.vid.0))),
        ("proposed_at", Json::Int(i128::from(version.created_at.0))),
        (
            "control_entry",
            recorded
                .control_entry
                .map_or(Json::Null, |entry| s(format!("{:032x}", entry.0))),
        ),
        ("already_recorded", Json::Bool(recorded.already_recorded)),
    ]);
    ctx.out.event(
        "rule_proposed",
        fields,
        &format!(
            "rule {} v{} is version {}{}; it is not active until an activation names it",
            version.rule.name(),
            version.rule.version(),
            hex(&version.rule.ir_digest()),
            if recorded.already_recorded {
                " (already recorded; nothing was written)"
            } else {
                ""
            }
        ),
    );
    Ok(())
}

fn version_json(version: &RuleVersionRow) -> Json {
    let rule = &version.rule;
    obj(vec![
        ("rule", s(rule.name())),
        ("version", Json::Int(i128::from(rule.version()))),
        ("event_kind", s(rule.event().name())),
        ("ir_digest", s(hex(&rule.ir_digest()))),
        ("proposed_at", Json::Int(i128::from(version.created_at.0))),
        ("accounts", strings(&rule.dependencies().accounts)),
    ])
}

fn binding_json(name: &RuleNameRow) -> Vec<Json> {
    name.bindings
        .0
        .iter()
        .map(|binding| {
            obj(vec![
                ("rule", s(&name.name)),
                ("effective_from", s(binding.effective_from.render())),
                ("ir_digest", s(hex(&binding.ir_digest))),
            ])
        })
        .collect()
}

/// `fa rule activate`: plan with `--dry-run`, or commit an approved plan.
fn activate(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let approvals = args.flag_all("--approval");
    match (args.switch("--dry-run"), args.flag("--plan")) {
        (true, None) if approvals.is_empty() => plan_activation(ctx, args),
        (false, Some(path)) => {
            if args.flag("--from").is_some() || args.flag("--key").is_some() {
                return Err(usage(
                    "--from and --key belong to the plan; --plan carries what its approvals bind",
                    COMMIT,
                ));
            }
            commit_activation(ctx, args, path, &approvals)
        }
        (true, _) => Err(usage(
            "--dry-run plans an activation and commits nothing; it takes no --plan or --approval",
            ACTIVATE,
        )),
        (false, None) => Err(usage(
            "rule activate needs --dry-run (to plan an activation) or --plan (to commit an approved one)",
            format!(
                "{ACTIVATE}; then two approvers run `fa approve --proposal <proposal_digest> --as <approver>`; then {COMMIT}"
            ),
        )),
    }
}

fn plan_activation(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, target] = args.positional.as_slice() else {
        return Err(usage(
            "rule activate names one version's ir_digest",
            ACTIVATE,
        ));
    };
    let digest = digest_arg(target, ACTIVATE)?;
    let Some(from) = args.flag("--from") else {
        return Err(usage(
            "rule activate needs --from: the date it takes effect",
            ACTIVATE,
        ));
    };
    let from = DateDay::parse(from)
        .map_err(|e| usage(format!("--from `{from}`: {e:?}"), "--from YYYY-MM-DD"))?;
    let key = args.flag("--key").map_or_else(
        || format!("rule-activate:{}:{}", hex(&digest), from.render()),
        str::to_string,
    );
    let capability = ctx.capability(args, &["rule_change"])?;
    let book = ctx.books.open(args)?;
    let plan = book.plan_rule_activation(&capability, &digest, from, key.as_bytes())??;
    let proposal = plan
        .proposal_digest(book.context())
        .map_err(|e| Fail::Internal(format!("rule activation digest: {e}")))?;
    let encoded = hex(&plan
        .encode()
        .map_err(|e| Fail::Internal(format!("rule activation plan encoding: {e}")))?);
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "rule_activation_plan",
        vec![
            ("rule", s(&plan.rule_name)),
            ("ir_digest", s(hex(&plan.ir_digest))),
            ("effective_from", s(plan.effective_from.render())),
            ("principal", s(format!("{:032x}", plan.principal_ref.0))),
            ("proposal_digest", s(hex(&proposal))),
            ("bytes", s(&encoded)),
            ("scope", s("rule-activation-proposal")),
        ],
        &format!(
            "planned activating rule {} at version {} from {}; nothing was written. Two approvers who are not the planner approve proposal {} (`fa approve --proposal {}`); commit with `fa rule activate --plan <file|-> --approval <vid> --approval <vid>`.\nCanonical rule activation plan bytes (hex):\n{encoded}",
            plan.rule_name,
            hex(&plan.ir_digest),
            plan.effective_from.render(),
            hex(&proposal),
            hex(&proposal)
        ),
    );
    Ok(())
}

fn commit_activation(
    ctx: &mut Ctx<'_>,
    args: &Args,
    path: &str,
    approvals: &[&str],
) -> Result<(), Fail> {
    let bytes = read_plan_bytes(
        &ctx.files,
        path,
        RULE_ACTIVATION_PLAN_DOMAIN,
        "rule activation",
    )?;
    let plan = RuleActivationPlan::decode(&bytes).map_err(|e| {
        usage(
            format!("{path} is not a rule activation plan: {e}"),
            ACTIVATE,
        )
    })?;
    let capability = ctx.capability(args, &["rule_change"])?;
    let mut book = ctx.books.open(args)?;
    let digest = plan
        .proposal_digest(book.context())
        .map_err(|e| Fail::Internal(format!("rule activation digest: {e}")))?;
    let approvals = approvals
        .iter()
        .map(|v| {
            Ok(fa_model::ApprovalRef {
                approval_vid: parse_vid(v, "--approval")?,
                approved_digest: digest,
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let activated = book.activate_rule_version(&capability, plan, approvals)??;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "rule_activated",
        vec![
            ("rule", s(&activated.rule_name)),
            ("ir_digest", s(hex(&activated.binding.ir_digest))),
            (
                "effective_from",
                s(activated.binding.effective_from.render()),
            ),
            (
                "control_entry",
                s(format!("{:032x}", activated.control_entry.0)),
            ),
            (
                "recorded_at",
                Json::Int(i128::from(activated.recorded_at.0)),
            ),
            (
                "approvals",
                Json::Int(i128::try_from(activated.approvals).unwrap_or(i128::MAX)),
            ),
            ("already_recorded", Json::Bool(activated.already_recorded)),
        ],
        &format!(
            "{} rule {} at version {} from {} (record {})",
            if activated.already_recorded {
                "already activated:"
            } else {
                "activated"
            },
            activated.rule_name,
            hex(&activated.binding.ir_digest),
            activated.binding.effective_from.render(),
            activated.recorded_at.0
        ),
    );
    Ok(())
}

/// `fa rule derive --rule <ir_digest> --event <code|vid> [--input …] [--key K]`:
/// post the entry the version derives from the event. The kernel re-runs
/// the derivation in the commit and posts only what it derives.
fn derive(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "rule derive takes no positional; name the version with --rule",
            DERIVE,
        ));
    }
    let Some(target) = args.flag("--event") else {
        return Err(usage("rule derive needs --event", DERIVE));
    };
    let Some(rule) = args.flag("--rule") else {
        return derive_all(ctx, args, target);
    };
    let digest = digest_arg(rule, DERIVE)?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read", "post"])?;
    let mut selected = None;
    let mut book = ctx.books.open_admitted(args, |book| {
        let scope = book.read_scope(who, &cap)??;
        let seq = scope.admit_whole_book(None)??;
        selected = Some(book.rea_snapshot(Some(seq))?);
        Ok(())
    })?;
    let rea = selected.ok_or_else(|| Fail::Internal("event snapshot is missing".into()))?;
    let event = find_event(&rea, book.context().book_id, target).ok_or_else(|| {
        usage(
            format!("no event `{target}` in this book at {}", rea.known_at.0),
            "fa event list --book <dir> --json",
        )
    })?;
    let event_vid = event.vid;
    let (_, version) = book.rule_version(&digest, Some(rea.known_at), &cap)??;
    let rule = version
        .ok_or_else(|| {
            usage(
                format!("this book holds no rule version {}", hex(&digest)),
                "fa rule list names the versions; fa rule propose <file> journals one",
            )
        })?
        .rule;
    let given = inputs(&rule, args, &book.context().units)?;
    let key = match args.flag("--key") {
        Some(key) => key.to_string(),
        None => default_key(&digest, event_vid, &rule, &given)?,
    };
    let posted = book.derive_rule_entry(&cap, &digest, event_vid, &given, key.as_bytes())??;
    ctx.out.at_book(&book)?;
    crate::cli::emit_posted(&ctx.out, posted, "Original", false, None, None)
}

/// The request itself, within the 64-byte key bound: deriving the same
/// version over the same event with the same inputs is a retry.
fn default_key(
    digest: &[u8; 32],
    event: fgdb_types::VId,
    rule: &CompiledRule,
    inputs: &Inputs,
) -> Result<String, Fail> {
    Ok(hex(&fa_model::domain_digest(
        b"fa-cli:rule-derive-key:v1",
        &[
            digest,
            &event.0.to_le_bytes(),
            &fa_canon_inputs_digest(rule, inputs)?,
        ],
    )))
}

/// `fa rule derive --event <code|vid>` without `--rule`: every activated
/// rule whose version in force on the event's date reads this event's kind
/// derives its entry (plan §10.2 RecordEvent: the book's rules derive
/// entries from an event). A rule that declares inputs is reported as
/// skipped: derive it with `--rule` and `--input`. Each derivation is its
/// own entry under its default key; on a refusal the command stops with
/// it, and running it again is a retry of the derivations already posted.
fn derive_all(ctx: &mut Ctx<'_>, args: &Args, target: &str) -> Result<(), Fail> {
    if !args.flag_all("--input").is_empty() || args.flag("--key").is_some() {
        return Err(usage(
            "--input and --key name one rule's derivation: give --rule with them",
            DERIVE,
        ));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read", "post"])?;
    let mut selected = None;
    let mut book = ctx.books.open_admitted(args, |book| {
        let scope = book.read_scope(who, &cap)??;
        let seq = scope.admit_whole_book(None)??;
        selected = Some(book.rea_snapshot(Some(seq))?);
        Ok(())
    })?;
    let rea = selected.ok_or_else(|| Fail::Internal("event snapshot is missing".into()))?;
    let event = find_event(&rea, book.context().book_id, target).ok_or_else(|| {
        usage(
            format!("no event `{target}` in this book at {}", rea.known_at.0),
            "fa event list --book <dir> --json",
        )
    })?;
    let (_, names) = book.rule_names(Some(rea.known_at), &cap)??;
    let mut derived = Vec::new();
    let mut skipped = Vec::new();
    for name in &names {
        let Some(digest) = name.bindings.in_force(event.spec.occurred_on) else {
            continue;
        };
        let (_, version) = book.rule_version(&digest, Some(rea.known_at), &cap)??;
        let rule = version
            .ok_or_else(|| {
                Fail::Internal(format!(
                    "rule {} binds a version the book does not hold",
                    name.name
                ))
            })?
            .rule;
        if rule.event() != event.spec.kind {
            continue;
        }
        if !rule.inputs().is_empty() {
            skipped.push(obj(vec![
                ("rule", s(&name.name)),
                ("ir_digest", s(hex(&digest))),
                (
                    "reason",
                    s("it declares inputs: derive it with --rule and --input"),
                ),
            ]));
            continue;
        }
        let none = Inputs::new();
        let key = default_key(&digest, event.vid, &rule, &none)?;
        let posted = book.derive_rule_entry(&cap, &digest, event.vid, &none, key.as_bytes())??;
        let (entry_ref, recorded_at, already) = match posted {
            fa_journal::Posted::Committed {
                entry_ref,
                recorded_at,
                ..
            } => (entry_ref, recorded_at, false),
            fa_journal::Posted::AlreadyRecorded {
                entry_ref,
                recorded_at,
            } => (entry_ref, recorded_at, true),
        };
        derived.push(obj(vec![
            ("rule", s(&name.name)),
            ("ir_digest", s(hex(&digest))),
            ("vid", s(format!("{:032x}", entry_ref.vid.0))),
            ("recorded_at", Json::Int(i128::from(recorded_at.0))),
            ("already_recorded", Json::Bool(already)),
        ]));
    }
    ctx.out.at_book(&book)?;
    let human = format!(
        "event {}: {} rule-derived entr{} posted or already recorded, {} rule{} skipped",
        event.spec.code,
        derived.len(),
        if derived.len() == 1 { "y" } else { "ies" },
        skipped.len(),
        if skipped.len() == 1 { "" } else { "s" },
    );
    ctx.out.event(
        "rule_derivations",
        vec![
            ("event_code", s(&event.spec.code)),
            ("derived", Json::Arr(derived)),
            ("skipped", Json::Arr(skipped)),
        ],
        &human,
    );
    Ok(())
}

/// The inputs' digest, for a default key: deriving the same version over
/// the same event with the same inputs again is a retry.
fn fa_canon_inputs_digest(rule: &CompiledRule, inputs: &Inputs) -> Result<[u8; 32], Fail> {
    let bytes = fa::rule::encode_inputs(rule, inputs)
        .map_err(|e| usage(format!("the inputs do not fit the rule: {e}"), DERIVE))?;
    Ok(fa_model::domain_digest(
        fa::rule::CANON_INPUTS_DOMAIN,
        &[&bytes],
    ))
}

/// `fa rule list [--as-known-at HEAD|<seq>]`.
fn list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage("rule list takes no positional", LIST));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    let (at, versions) = book.rule_versions(known_at, &cap)??;
    let (_, names) = book.rule_names(Some(at), &cap)??;
    ctx.out.known_at(at);
    let human: Vec<String> = versions
        .iter()
        .map(|v| {
            format!(
                "{:<24} v{:<4} {:<12} {} (proposed at {})",
                v.rule.name(),
                v.rule.version(),
                v.rule.event().name(),
                hex(&v.rule.ir_digest()),
                v.created_at.0
            )
        })
        .collect();
    ctx.out.event(
        "rule_versions",
        vec![
            (
                "count",
                Json::Int(i128::try_from(versions.len()).unwrap_or(i128::MAX)),
            ),
            (
                "versions",
                Json::Arr(versions.iter().map(version_json).collect()),
            ),
            (
                "bindings",
                Json::Arr(names.iter().flat_map(binding_json).collect()),
            ),
        ],
        &if human.is_empty() {
            "no rule versions (fa rule propose <file>)".to_string()
        } else {
            human.join("\n")
        },
    );
    Ok(())
}

/// `fa rule show <ir_digest> [--as-known-at HEAD|<seq>]`.
fn show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, target] = args.positional.as_slice() else {
        return Err(usage("rule show names one version's ir_digest", SHOW));
    };
    let digest = digest_arg(target, SHOW)?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    let (at, version) = book.rule_version(&digest, known_at, &cap)??;
    ctx.out.known_at(at);
    let version = version.ok_or_else(|| {
        usage(
            format!(
                "this book holds no rule version {} at {}",
                hex(&digest),
                at.0
            ),
            format!(
                "{SHOW}   (fa rule list names the versions; fa rule propose <file> journals one)"
            ),
        )
    })?;
    let rule = &version.rule;
    let mut fields = rule_fields(rule);
    fields.push(("proposed_at", Json::Int(i128::from(version.created_at.0))));
    fields.extend(dependency_fields(rule, &book.context().units));
    fields.push(("source", s(&version.spec.source)));
    ctx.out.event(
        "rule_version",
        fields,
        &format!(
            "rule {} v{} for {} events, version {} (proposed at {})\nposts to {}\n\n{}",
            rule.name(),
            rule.version(),
            rule.event().name(),
            hex(&rule.ir_digest()),
            version.created_at.0,
            accounts_line(rule),
            version.spec.source
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

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Debit => "debit",
        Side::Credit => "credit",
    }
}

fn leg_json(leg: &fa::rule::DerivedLeg, units: &fa_money::UnitRegistry) -> Json {
    obj(vec![
        ("side", s(side_name(leg.side))),
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

/// `fa rule eval (<rule-file|-> | --rule <ir_digest>) --event <code|vid>
/// [--input <name>=<value>]...`.
fn eval(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let Some(target) = args.flag("--event") else {
        return Err(usage("rule eval needs --event", EVAL));
    };
    let from_journal = match (args.flag("--rule"), args.positional.len()) {
        (Some(digest), 2) => Some(digest_arg(digest, EVAL)?),
        (None, 3) => None,
        _ => {
            return Err(usage(
                "rule eval takes one rule file or `--rule <ir_digest>`, not both",
                EVAL,
            ));
        }
    };
    let text = match from_journal {
        Some(_) => None,
        None => Some(ctx.files.read_text(source(args, EVAL)?)?),
    };
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
    let rule = match (&text, from_journal) {
        (Some(text), _) => compile_rule(book.context(), text).map_err(Fail::Refusal)?,
        (None, Some(digest)) => {
            let (_, version) = book.rule_version(&digest, Some(rea.known_at), &cap)??;
            version
                .ok_or_else(|| {
                    usage(
                        format!(
                            "this book holds no rule version {} at {}",
                            hex(&digest),
                            rea.known_at.0
                        ),
                        "fa rule list names the versions; fa rule propose <file> journals one",
                    )
                })?
                .rule
        }
        (None, None) => return Err(Fail::Internal("rule eval selected no rule".into())),
    };
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
            side_name(leg.side),
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
