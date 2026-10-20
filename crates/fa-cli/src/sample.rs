//! `fa sample uniform|mus` (plan §11.7; beads fa-kaf7, fa-vpk): a
//! reproducible audit sample over one account's open items at one recorded
//! coordinate. Nothing is written to the book.
//!
//! The population is the account's open items on its normal-balance side
//! with a positive open amount, in one unit. Each item is
//! `<entry vid hex>:<ordinal, five digits>` with its open amount as book
//! value; fa-lantern orders the items canonically and digests them. Open
//! items on the other side (credits in a debit-normal account, and the
//! reverse) cannot carry a positive book value, so they are listed as
//! excluded, to be tested separately, never silently dropped.
//!
//! Selection is fa-lantern's: a pure function of the population digest, the
//! declared seed and the parameters, over PCG64DXSM (NumPy's
//! `np.random.PCG64DXSM(seed)`, reproducible with the snippet documented on
//! `fa_lantern::sample::Pcg64Dxsm`). The seed is a declared input; nothing
//! draws entropy. The `sample_digest` binds the method, population digest,
//! seed, parameters and selected item ids; it is recomputed, not retained.

use std::collections::{BTreeMap, BTreeSet};

use fa_lantern::LanternError;
use fa_lantern::sample::{self, MusSelectionBasis, PopulationItem, SamplePopulation};
use fa_model::account_vid;
use fa_money::{Amount, Side, UnitId};
use fa_registers::open_items::OpenItem;
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, hex, known_at_flag, registered_unit_code, render_amount, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa sample uniform --account <code> --seed <u64> --size <n> [--as-of YYYY-MM-DD] [--as-known-at HEAD|<seq>|<RFC3339>] --json, or fa sample mus --account <code> --seed <u64> --interval \"<amount> <UNIT>\" [...]";

const EVALUATE_EXAMPLE: &str = "fa sample evaluate --account <code> --seed <u64> --interval \"<amount> <UNIT>\" --as-known-at <seq> [--as-of YYYY-MM-DD] --audited <audited.json|-> --confidence 90|95|99 --json";

pub(crate) fn sample_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let method = match args.positional.get(1).map(String::as_str) {
        Some(method @ ("uniform" | "mus" | "evaluate")) if args.positional.len() == 2 => method,
        Some(other) if args.positional.len() == 2 => {
            return Err(usage(format!("unknown sampling method `{other}`"), EXAMPLE));
        }
        _ => {
            return Err(usage(
                "sample needs exactly one of uniform, mus or evaluate",
                EXAMPLE,
            ));
        }
    };
    for flag in [
        "--account",
        "--seed",
        "--size",
        "--interval",
        "--as-of",
        "--as-known-at",
        "--known-at",
        "--audited",
        "--confidence",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(format!("sample takes only one {flag}"), EXAMPLE));
        }
    }
    let code = args.require("--account", "<account code>, for example 1200")?;
    let seed = args
        .require("--seed", "<u64>, the declared seed")?
        .parse::<u64>()
        .map_err(|_| {
            usage(
                "--seed must be an unsigned 64-bit integer; the seed is declared, never drawn",
                "--seed 20260115",
            )
        })?;
    if method != "evaluate" {
        for flag in ["--audited", "--confidence"] {
            if args.flag(flag).is_some() {
                return Err(usage(
                    format!(
                        "{flag} belongs to `fa sample evaluate`, which evaluates a drawn MUS sample"
                    ),
                    EVALUATE_EXAMPLE,
                ));
            }
        }
    }
    // Evaluation re-draws the MUS sample it evaluates, so it is bound to the
    // sample's recorded sequence, never to a moving HEAD.
    let evaluation = if method == "evaluate" {
        let recorded = args.flag("--as-known-at");
        if !recorded.is_some_and(|seq| !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit())) {
            return Err(usage(
                "evaluation re-draws the sample at its recorded sequence: pass --as-known-at <seq>",
                "the sample's replay_command names it; fa sample evaluate takes the same --account, --seed, --interval, --as-of and --as-known-at",
            ));
        }
        let confidence_bps = match args.require("--confidence", "90, 95 or 99 (percent)")? {
            "90" => 9_000,
            "95" => 9_500,
            "99" => 9_900,
            other => {
                return Err(usage(
                    format!("--confidence `{other}` is not 90, 95 or 99 (percent)"),
                    "--confidence 95",
                ));
            }
        };
        let audited = ctx
            .files
            .read_text(args.require("--audited", "<audited.json|->")?)?;
        Some((confidence_bps, audited))
    } else {
        None
    };
    let (size, interval) = match method {
        "uniform" => {
            if args.flag("--interval").is_some() {
                return Err(usage(
                    "--interval is the MUS sampling interval; a uniform sample takes --size",
                    EXAMPLE,
                ));
            }
            let size = args
                .require("--size", "<n>, the number of items to select")?
                .parse::<usize>()
                .ok()
                .filter(|size| *size > 0)
                .ok_or_else(|| usage("--size must be a positive integer", "--size 25"))?;
            (Some(size), None)
        }
        _ => {
            if args.flag("--size").is_some() {
                return Err(usage(
                    "--size is a uniform sample's size; an MUS sample takes --interval",
                    EXAMPLE,
                ));
            }
            (
                None,
                Some(args.require(
                    "--interval",
                    "\"<amount> <UNIT>\", for example \"500.00 USD\"",
                )?),
            )
        }
    };
    let as_of = args
        .flag("--as-of")
        .map(|date| {
            DateDay::parse(date).map_err(|e| {
                usage(
                    format!("{e}; --as-of requires a civil date"),
                    "--as-of YYYY-MM-DD",
                )
            })
        })
        .transpose()?;
    // Authority precedes observation (doctrine 8, fa-0x0): the sample
    // discloses the account's open items, so the capability is admitted as
    // current read authority on open, and each read is judged by the scope
    // caveats before its query, exactly as `fa open-items` is.
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        book.read_scope(who, &capability)??;
        Ok(())
    })?;
    let (requested, _) = known_at_flag(args, &book, &ctx.out)?;
    let account = account_vid(book.context().book_id, code);
    let (known_at, items) = match as_of {
        Some(day) => {
            // The snapshot reaches every period that starts by its day.
            book.read_scope(who, &capability)??
                .admit_as_of(day, requested)??;
            let snapshot = book.open_items_as_of(Some(account), day, requested)?;
            ctx.out.effective(format!("as-of:{day}"));
            (snapshot.known_at, snapshot.items)
        }
        None => {
            // Open items reach the whole book.
            book.read_scope(who, &capability)??.admit_report(
                &fa::ReportSelection::OpenItems {
                    account: Some(account),
                },
                requested,
            )??;
            let report = book.open_items_report(Some(account), requested)?;
            (report.known_at, report.items)
        }
    };
    let row = book
        .accounts_at(known_at, &capability)??
        .into_iter()
        .find(|row| row.vid == account)
        .ok_or_else(|| {
            usage(
                format!("no account `{code}` at sequence {}", known_at.0),
                "fa chart list --json names the accounts",
            )
        })?;
    let normal = if row.normal_balance == 0 {
        Side::Debit
    } else {
        Side::Credit
    };
    let units = &book.context().units;
    let (population, excluded) = population(code, &items, account, normal, as_of, units)?;
    let unit_code = registered_unit_code(population.unit, units)?;
    let render = |amount: Amount| render_amount(amount, units);

    let mut fields: Vec<(&str, Json)> = Vec::new();
    let (parameters, digest, selected) = match (size, interval) {
        (Some(size), _) => {
            let plan = sample::sample_uniform(&population, seed, size).map_err(sample_error)?;
            let rows = plan
                .selected
                .iter()
                .map(|item| selected_row(item, None, None, &render))
                .collect::<Result<Vec<_>, Fail>>()?;
            fields.extend([
                ("size", Json::Int(size as i128)),
                ("interval", Json::Null),
                ("start", Json::Null),
                ("top_stratum_count", Json::Null),
                ("systematic_count", Json::Null),
            ]);
            (
                plan.certificate.parameters_summary,
                plan.certificate.certificate_oid,
                rows,
            )
        }
        (None, Some(text)) => {
            let interval = Amount::parse(text, units).map_err(|e| {
                usage(
                    format!("--interval: {e}"),
                    format!("--interval \"500.00 {unit_code}\" (the population's unit)"),
                )
            })?;
            let plan = sample::sample_mus(&population, seed, interval).map_err(sample_error)?;
            if let Some((confidence_bps, audited)) = &evaluation {
                let summary = Evaluated {
                    code,
                    unit_code: &unit_code,
                    as_of,
                    known_at,
                    seed,
                    population: &population,
                };
                return evaluate(&ctx.out, units, &summary, &plan, *confidence_bps, audited);
            }
            let rows = plan
                .selected
                .iter()
                .map(|item| {
                    let (basis, hit) = match item.basis {
                        MusSelectionBasis::TopStratumHighValue => ("top_stratum", None),
                        MusSelectionBasis::SystematicHit {
                            hit_dollar_mantissa,
                        } => (
                            "systematic",
                            Some(Amount::new(population.unit, hit_dollar_mantissa)),
                        ),
                    };
                    let item = PopulationItem {
                        item_id: item.item_id.clone(),
                        reference_vid: item.reference_vid,
                        stratum: None,
                        book_value: item.book_value,
                    };
                    selected_row(&item, Some(basis), hit, &render)
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            fields.extend([
                ("size", Json::Null),
                ("interval", s(render(plan.interval)?)),
                (
                    "start",
                    s(render(Amount::new(
                        population.unit,
                        plan.start_dollar_mantissa,
                    ))?),
                ),
                (
                    "top_stratum_count",
                    Json::Int(plan.top_stratum_count as i128),
                ),
                (
                    "systematic_count",
                    Json::Int(plan.systematic_sample_count as i128),
                ),
            ]);
            (
                plan.certificate.parameters_summary,
                plan.certificate.certificate_oid,
                rows,
            )
        }
        (None, None) => return Err(Fail::Internal("sample method without parameters".into())),
    };

    let excluded_rows = excluded
        .iter()
        .map(|item| {
            Ok(obj(vec![
                ("item_id", s(item_id(item))),
                ("entry", s(format!("{:032x}", item.entry.0))),
                ("ordinal", Json::Int(i128::from(item.ordinal))),
                (
                    "side",
                    s(if item.side == Side::Debit {
                        "debit"
                    } else {
                        "credit"
                    }),
                ),
                (
                    "open",
                    s(render(Amount::new(UnitId(item.unit_id), item.open))?),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let replay = format!(
        "fa sample {method} --account {code} --seed {seed} {} --as-known-at {}{}",
        match (size, interval) {
            (Some(size), _) => format!("--size {size}"),
            (_, interval) => format!("--interval \"{}\"", interval.unwrap_or_default()),
        },
        known_at.0,
        as_of.map_or(String::new(), |day| format!(" --as-of {day}")),
    );
    let total = render(population.total_book_value)?;
    let human = format!(
        "{method} sample of {} from {} open items of {code} ({total}) at known-at {}, seed {seed}; {} excluded on the other side\n{}",
        selected.len(),
        population.items.len(),
        known_at.0,
        excluded.len(),
        replay
    );
    ctx.out.known_at(known_at);
    let mut event = vec![
        ("method", s(method)),
        ("account", s(code)),
        ("unit", s(unit_code)),
        ("as_of", as_of.map_or(Json::Null, |day| s(day.render()))),
        ("known_at", Json::Int(i128::from(known_at.0))),
        ("seed", Json::Int(i128::from(seed))),
        (
            "population_count",
            Json::Int(population.items.len() as i128),
        ),
        ("population_total", s(total)),
        ("population_digest", s(hex(&population.population_digest))),
        ("parameters", s(parameters)),
        ("selected_count", Json::Int(selected.len() as i128)),
        ("selected", Json::Arr(selected)),
        ("excluded", Json::Arr(excluded_rows)),
        ("sample_digest", s(hex(&digest.0))),
        ("replay_command", s(replay)),
    ];
    event.extend(fields);
    ctx.out.event("sample_drawn", event, &human);
    Ok(())
}

/// `<entry vid hex>:<ordinal>`, the ordinal zero-padded so the canonical
/// (lexicographic) population order is entry, then leg order.
fn item_id(item: &OpenItem) -> String {
    format!("{:032x}:{:05}", item.entry.0, item.ordinal)
}

/// The account's open items on its normal side with a positive open amount,
/// and those on the other side (excluded, to be tested separately). Fully
/// applied items (open zero) are not open and are in neither.
fn population<'a>(
    code: &str,
    items: &'a [OpenItem],
    account: VId,
    normal: Side,
    as_of: Option<DateDay>,
    units: &fa_money::UnitRegistry,
) -> Result<(SamplePopulation, Vec<&'a OpenItem>), Fail> {
    let mut members = Vec::new();
    let mut excluded = Vec::new();
    let mut unit_ids = BTreeSet::new();
    for item in items.iter().filter(|item| item.account == account) {
        if item.open == 0 {
            continue;
        }
        if item.side == normal && item.open > 0 {
            unit_ids.insert(item.unit_id);
            members.push(PopulationItem {
                item_id: item_id(item),
                reference_vid: item.entry,
                stratum: None,
                book_value: Amount::new(UnitId(item.unit_id), item.open),
            });
        } else {
            excluded.push(item);
        }
    }
    let side = if normal == Side::Debit {
        "debit"
    } else {
        "credit"
    };
    let unit = match unit_ids.len() {
        0 => {
            return Err(usage(
                format!(
                    "account {code} has no open item on its normal ({side}) side with a positive open amount to sample"
                ),
                format!("fa open-items --account {code} --json lists its open items"),
            ));
        }
        1 => UnitId(*unit_ids.first().unwrap_or(&0)),
        _ => {
            let codes = unit_ids
                .iter()
                .map(|unit| registered_unit_code(UnitId(*unit), units))
                .collect::<Result<Vec<_>, Fail>>()?;
            return Err(usage(
                format!(
                    "account {code}'s open items carry {} units ({}); a sample's book values share one unit",
                    codes.len(),
                    codes.join(", ")
                ),
                "sample an account whose open items are in one unit",
            ));
        }
    };
    let name = match as_of {
        Some(day) => format!("open-items {code} {side} as-of {day}"),
        None => format!("open-items {code} {side}"),
    };
    let population = SamplePopulation::new(name, unit, members).map_err(sample_error)?;
    Ok((population, excluded))
}

fn selected_row(
    item: &PopulationItem,
    basis: Option<&str>,
    hit: Option<Amount>,
    render: &dyn Fn(Amount) -> Result<String, Fail>,
) -> Result<Json, Fail> {
    let (entry, ordinal) = item
        .item_id
        .split_once(':')
        .ok_or_else(|| Fail::Internal(format!("sample item id `{}`", item.item_id)))?;
    let ordinal = ordinal
        .parse::<u16>()
        .map_err(|_| Fail::Internal(format!("sample item id `{}`", item.item_id)))?;
    Ok(obj(vec![
        ("item_id", s(item.item_id.as_str())),
        ("entry", s(entry)),
        ("ordinal", Json::Int(i128::from(ordinal))),
        ("book_value", s(render(item.book_value)?)),
        ("basis", basis.map_or(Json::Null, s)),
        ("hit", hit.map(render).transpose()?.map_or(Json::Null, s)),
    ]))
}

const AUDITED_SHAPE: &str = "--audited takes {\"items\":[{\"item_id\":\"<selected item_id>\",\"audited\":\"<amount> <UNIT>\"}, ...]}, one row for every item the sample selected";

/// The drawn MUS sample an evaluation answers.
struct Evaluated<'a> {
    code: &'a str,
    unit_code: &'a str,
    as_of: Option<DateDay>,
    known_at: CommitSeq,
    seed: u64,
    population: &'a SamplePopulation,
}

/// `fa sample evaluate`: the Stringer upper misstatement limit over the
/// auditor's values for exactly the items the re-drawn MUS sample selected.
/// Book values come from that sample, never from the caller; every selected
/// item needs exactly one audited value and no other item is accepted.
/// Overstatements are evaluated (understatements are counted, not bounded);
/// every component is exact and rounded up to the unit (fa-lantern).
fn evaluate(
    out: &Out,
    units: &fa_money::UnitRegistry,
    drawn: &Evaluated<'_>,
    plan: &sample::MusSamplePlan,
    confidence_bps: u32,
    audited: &str,
) -> Result<(), Fail> {
    let doc = crate::json::parse(audited)
        .map_err(|e| usage(format!("invalid --audited JSON: {e}"), AUDITED_SHAPE))?;
    let rows = match &doc {
        Json::Obj(fields) if matches!(fields.as_slice(), [(key, _)] if key == "items") => doc
            .get("items")
            .and_then(Json::as_arr)
            .ok_or_else(|| usage("--audited `items` is not an array", AUDITED_SHAPE))?,
        _ => {
            return Err(usage(
                "--audited is not an object with only `items`",
                AUDITED_SHAPE,
            ));
        }
    };
    let mut values: BTreeMap<&str, Amount> = BTreeMap::new();
    for row in rows {
        let Json::Obj(fields) = row else {
            return Err(usage("an --audited row is not an object", AUDITED_SHAPE));
        };
        if fields.len() != 2 || row.get("item_id").is_none() || row.get("audited").is_none() {
            return Err(usage(
                "an --audited row has exactly item_id and audited",
                AUDITED_SHAPE,
            ));
        }
        let (Some(id), Some(text)) = (
            row.get("item_id").and_then(Json::as_str),
            row.get("audited").and_then(Json::as_str),
        ) else {
            return Err(usage(
                "item_id and audited are strings; amounts are \"<amount> <UNIT>\"",
                AUDITED_SHAPE,
            ));
        };
        let value = Amount::parse(text, units)
            .map_err(|e| format!("audited value of {id}: {e}"))
            .and_then(|value| {
                if value.unit == drawn.population.unit {
                    Ok(value)
                } else {
                    Err(format!(
                        "audited value of {id} is not in the sample's unit {}",
                        drawn.unit_code
                    ))
                }
            })
            .map_err(|message| {
                usage(
                    message,
                    format!("\"95.00 {}\", in the sample's unit", drawn.unit_code),
                )
            })?;
        if values.insert(id, value).is_some() {
            return Err(usage(
                format!("{id} has more than one audited value"),
                AUDITED_SHAPE,
            ));
        }
    }
    // The audited set must be exactly the selection: an item the sample did
    // not select, or a selected item left out, answers another sample.
    let selected: BTreeSet<&str> = plan.selected.iter().map(|i| i.item_id.as_str()).collect();
    let missing: Vec<&str> = selected
        .iter()
        .copied()
        .filter(|id| !values.contains_key(id))
        .collect();
    let unexpected: Vec<&str> = values
        .keys()
        .copied()
        .filter(|id| !selected.contains(id))
        .collect();
    if !missing.is_empty() || !unexpected.is_empty() {
        return Err(Fail::Verification {
            message: format!(
                "the audited values do not answer this sample: {} selected item(s) without a value, {} value(s) for items it did not select",
                missing.len(),
                unexpected.len()
            ),
            detail: obj(vec![
                ("missing", Json::Arr(missing.iter().map(|id| s(*id)).collect())),
                (
                    "unexpected",
                    Json::Arr(unexpected.iter().map(|id| s(*id)).collect()),
                ),
                ("sample_digest", s(hex(&plan.certificate.certificate_oid.0))),
            ]),
            cite: None,
            fix: Some(
                "audit exactly the selected items of the sample drawn with the same --account, --seed, --interval, --as-of and --as-known-at (fa sample mus)".into(),
            ),
        });
    }
    let items = plan
        .selected
        .iter()
        .map(|item| {
            let audited_value = values
                .get(item.item_id.as_str())
                .copied()
                .ok_or_else(|| Fail::Internal(format!("no audited value for {}", item.item_id)))?;
            Ok(sample::AuditedSampleItem {
                item_id: item.item_id.clone(),
                book_value: item.book_value,
                audited_value,
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let result = sample::evaluate_stringer_bound(plan.interval, confidence_bps, &items)
        .map_err(sample_error)?;
    let render = |amount: Amount| render_amount(amount, units);
    let taintings: BTreeMap<&str, String> = result
        .ranked_taintings
        .iter()
        .map(|(id, rate)| (id.as_str(), rate.to_string()))
        .collect();
    let ranks: BTreeMap<&str, usize> = result
        .ranked_taintings
        .iter()
        .enumerate()
        .map(|(rank, (id, _))| (id.as_str(), rank + 1))
        .collect();
    let mut misstatements = Vec::new();
    let mut understatements = 0usize;
    for item in &items {
        let difference = item
            .book_value
            .mantissa
            .checked_sub(item.audited_value.mantissa)
            .ok_or_else(|| Fail::Internal("sample overstatement overflows".into()))?;
        if difference < 0 {
            understatements += 1;
        }
        if difference <= 0 {
            continue;
        }
        let id = item.item_id.as_str();
        misstatements.push(obj(vec![
            ("item_id", s(id)),
            ("book_value", s(render(item.book_value)?)),
            ("audited_value", s(render(item.audited_value)?)),
            (
                "overstatement",
                s(render(Amount::new(drawn.population.unit, difference))?),
            ),
            (
                "top_stratum",
                Json::Bool(item.book_value.mantissa >= plan.interval.mantissa),
            ),
            (
                "tainting",
                taintings.get(id).map_or(Json::Null, |t| s(t.as_str())),
            ),
            (
                "rank",
                ranks
                    .get(id)
                    .map_or(Json::Null, |rank| Json::Int(*rank as i128)),
            ),
        ]));
    }
    let limit = render(result.upper_misstatement_limit)?;
    let human = format!(
        "Stringer evaluation at {}% of the MUS sample of {} ({} items, interval {}): upper misstatement limit {limit}; basic precision {}, most likely error {}, incremental allowance {}; {} overstated, {understatements} understated",
        confidence_bps / 100,
        drawn.code,
        items.len(),
        render(plan.interval)?,
        render(result.basic_precision)?,
        render(result.most_likely_error)?,
        render(result.incremental_allowance)?,
        misstatements.len(),
    );
    out.known_at(drawn.known_at);
    out.event(
        "sample_evaluated",
        vec![
            ("account", s(drawn.code)),
            ("unit", s(drawn.unit_code)),
            (
                "as_of",
                drawn.as_of.map_or(Json::Null, |day| s(day.render())),
            ),
            ("known_at", Json::Int(i128::from(drawn.known_at.0))),
            ("seed", Json::Int(i128::from(drawn.seed))),
            ("interval", s(render(plan.interval)?)),
            (
                "confidence_percent",
                Json::Int(i128::from(confidence_bps / 100)),
            ),
            (
                "population_digest",
                s(hex(&drawn.population.population_digest)),
            ),
            ("sample_digest", s(hex(&plan.certificate.certificate_oid.0))),
            ("sample_size", Json::Int(items.len() as i128)),
            (
                "misstatement_count",
                Json::Int(result.misstatement_count as i128),
            ),
            ("understatement_count", Json::Int(understatements as i128)),
            (
                "top_stratum_misstatement",
                s(render(result.top_stratum_misstatement)?),
            ),
            ("basic_precision", s(render(result.basic_precision)?)),
            ("most_likely_error", s(render(result.most_likely_error)?)),
            (
                "incremental_allowance",
                s(render(result.incremental_allowance)?),
            ),
            ("upper_misstatement_limit", s(limit)),
            (
                "upper_misstatement_limit_exact",
                s(result.upper_misstatement_limit_exact.to_string()),
            ),
            ("misstatements", Json::Arr(misstatements)),
        ],
        &human,
    );
    Ok(())
}

/// A sampling parameter outside its domain (size beyond the population, an
/// interval in another unit or not positive) is a usage error; anything else
/// from the sampler is a defect of this build.
fn sample_error(error: LanternError) -> Fail {
    match error {
        LanternError::Parameter { name, message, .. } => usage(
            format!("sample {name}: {message}"),
            "fa open-items --account <code> --json shows the population; choose --size within it, or an --interval in its unit",
        ),
        other => Fail::Internal(format!("sample: {other}")),
    }
}
