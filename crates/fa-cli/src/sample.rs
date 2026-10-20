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

use std::collections::BTreeSet;

use fa_lantern::LanternError;
use fa_lantern::sample::{self, MusSelectionBasis, PopulationItem, SamplePopulation};
use fa_model::account_vid;
use fa_money::{Amount, Side, UnitId};
use fa_policy::Op;
use fa_registers::open_items::OpenItem;
use fa_time::DateDay;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, known_at_flag, registered_unit_code, render_amount, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa sample uniform --account <code> --seed <u64> --size <n> [--as-of YYYY-MM-DD] [--as-known-at HEAD|<seq>|<RFC3339>] --json, or fa sample mus --account <code> --seed <u64> --interval \"<amount> <UNIT>\" [...]";

pub(crate) fn sample_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let method = match args.positional.get(1).map(String::as_str) {
        Some(method @ ("uniform" | "mus")) if args.positional.len() == 2 => method,
        Some(other) if args.positional.len() == 2 => {
            return Err(usage(format!("unknown sampling method `{other}`"), EXAMPLE));
        }
        _ => {
            return Err(usage(
                "sample needs exactly one method: uniform or mus",
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
    // Authority precedes observation: the sample discloses the account's
    // open items, so read is checked before the book is read.
    let capability = ctx.capability(args, &["read"])?;
    fa_policy::require(&capability, Op::Read, "drawing an audit sample")
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    let book = ctx.books.open(args)?;
    let (requested, _) = known_at_flag(args, &book, &ctx.out)?;
    let account = account_vid(book.context().book_id, code);
    let (known_at, items) = match as_of {
        Some(day) => {
            let snapshot = book.open_items_as_of(Some(account), day, requested)?;
            ctx.out.effective(format!("as-of:{day}"));
            (snapshot.known_at, snapshot.items)
        }
        None => {
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
