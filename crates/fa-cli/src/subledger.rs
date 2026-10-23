//! Native AR/AP subledgers: one party-qualified control leaf and a literal
//! journal reconciliation at an explicit accounting coordinate (plan §5.6).
//! There is no second posting or mutable subledger balance.

use fa::{NativeSubledger, NativeSubledgerKind, NativeSubledgerSpec};
use fa_model::account_vid;
use fa_money::{Amount, UnitId};
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, date_flag, known_at_read_flag, registered_unit_code, render_amount, usage,
};
use crate::json::{Json, obj, s};

const ADD: &str =
    "fa subledger add AR --control 1200 --kind receivables --name \"Trade receivables\"";
const VERIFY: &str = "fa subledger verify AR --as-of YYYY-MM-DD [--as-known-at HEAD|<seq>]";
const HELP: &str = "fa subledger add <code> --control <account> --kind receivables|payables [--name <name>] | fa subledger list | fa subledger show <code> | fa subledger verify <code> --as-of YYYY-MM-DD";

pub(crate) fn subledger_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let sub = args.positional.get(1).map(String::as_str);
    if matches!(
        sub,
        Some("detail" | "feed" | "verify-feed" | "reconcile-feed")
    ) {
        return crate::external_subledger::command(ctx, args);
    }
    if args.switch("--certify") || args.flag("--certificate-out").is_some() {
        return Err(usage(
            "subledger certification is available for reconcile-feed",
            HELP,
        ));
    }
    if args.switch("--dry-run") {
        return Err(usage("--dry-run rehearses subledger feed only", HELP));
    }
    let allowed: &[&str] = match sub {
        Some("add") => &["--control", "--kind", "--name", "--date", "--key"],
        Some("list" | "show") => &["--as-known-at"],
        Some("verify") => &["--as-of", "--as-known-at"],
        _ => return Err(usage("subledger needs add, list, show or verify", HELP)),
    };
    for flag in [
        "--control",
        "--kind",
        "--name",
        "--date",
        "--key",
        "--as-known-at",
        "--as-of",
        "--input",
        "--out",
        "--document",
        "--description",
        "--plan-out",
    ] {
        let values = args.flag_all(flag);
        if !values.is_empty() && !allowed.contains(&flag) {
            return Err(usage(
                format!(
                    "{flag} is not an input to subledger {}",
                    sub.unwrap_or_default()
                ),
                HELP,
            ));
        }
        if values.len() > 1 {
            return Err(usage(format!("{flag} may be supplied only once"), HELP));
        }
    }
    match sub {
        Some("add") => add(ctx, args),
        Some("list" | "show") => list_or_show(ctx, args),
        Some("verify") => verify(ctx, args),
        _ => Err(usage("unknown subledger command", HELP)),
    }
}

fn code_argument(args: &Args, example: &str) -> Result<String, Fail> {
    let [_, _, code] = args.positional.as_slice() else {
        return Err(usage("name exactly one subledger code", example));
    };
    Ok(code.clone())
}

fn summary(subledger: &NativeSubledger, accounts: &[fa_journal::AccountRow]) -> Result<Json, Fail> {
    let control = accounts
        .iter()
        .find(|account| account.vid == subledger.spec.control_account)
        .ok_or_else(|| {
            Fail::Book(fa::BookError::Kernel(fa_journal::KernelError::Corrupt(
                "native subledger control account is absent at its recorded coordinate".into(),
            )))
        })?;
    Ok(obj(vec![
        ("code", s(&subledger.spec.code)),
        ("name", s(&subledger.spec.name)),
        ("kind", s(subledger.spec.kind.name())),
        ("vid", s(format!("{:032x}", subledger.vid.0))),
        ("control_account", s(&control.code)),
        ("control_vid", s(format!("{:032x}", control.vid.0))),
        (
            "control_entry",
            s(format!("{:032x}", subledger.entry.vid.0)),
        ),
        (
            "recorded_at",
            Json::Int(i128::from(subledger.recorded_at.0)),
        ),
    ]))
}

fn add(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let code = code_argument(args, ADD)?;
    let control = args.require("--control", "<GL control leaf account code>")?;
    let kind_text = args.require("--kind", "receivables|payables")?;
    let kind = NativeSubledgerKind::parse(kind_text)
        .ok_or_else(|| usage(format!("unknown native subledger kind {kind_text}"), ADD))?;
    let name = args.flag("--name").unwrap_or(&code).to_string();
    let key = args
        .flag("--key")
        .map_or_else(|| format!("subledger:{code}"), str::to_string);
    let date = date_flag(args, DateDay(0))?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read", "schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rea_change(who, &cap)??;
        crate::rea::admit_read(book, who, &cap)
    })?;
    let spec = NativeSubledgerSpec {
        code,
        name,
        kind,
        control_account: account_vid(book.context().book_id, control),
    };
    let recorded = book.create_native_subledger(&spec, who, date, key.as_bytes(), &cap)??;
    let accounts = book.accounts_at(book.head()?, &cap)??;
    let data = summary(&recorded.subledger, &accounts)?;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "subledger_recorded",
        vec![
            ("subledger", data),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
        ],
        &format!(
            "{} {} uses control account {control}; every control leg must name a party{}",
            spec.kind.name(),
            spec.code,
            if recorded.already_recorded {
                " (already recorded)"
            } else {
                ""
            },
        ),
    );
    Ok(())
}

fn list_or_show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let show = args.positional.get(1).is_some_and(|sub| sub == "show");
    let selected = if show {
        Some(code_argument(args, "fa subledger show <code>")?)
    } else {
        if args.positional.len() != 2 {
            return Err(usage(
                "subledger list takes no positional argument",
                "fa subledger list",
            ));
        }
        None
    };
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    let subledgers = book.native_subledgers(known_at, &cap)??;
    let known_at = known_at.unwrap_or(book.head()?);
    let accounts = book.accounts_at(known_at, &cap)??;
    let selected_rows: Vec<_> = subledgers
        .iter()
        .filter(|subledger| {
            selected
                .as_ref()
                .is_none_or(|code| &subledger.spec.code == code)
        })
        .collect();
    if selected.is_some() && selected_rows.is_empty() {
        return Err(usage(
            format!(
                "no subledger {} at sequence {}",
                selected.unwrap_or_default(),
                known_at.0
            ),
            "fa subledger list --as-known-at <seq> --json",
        ));
    }
    let rows = selected_rows
        .iter()
        .map(|subledger| summary(subledger, &accounts))
        .collect::<Result<Vec<_>, _>>()?;
    let human = selected_rows
        .iter()
        .map(|subledger| {
            let account = accounts
                .iter()
                .find(|a| a.vid == subledger.spec.control_account);
            format!(
                "{:<16} {:<4} control {:<12} recorded {}",
                subledger.spec.code,
                subledger.spec.kind.name(),
                account.map_or("?", |a| a.code.as_str()),
                subledger.recorded_at.0,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ctx.out.at_book(&book)?;
    ctx.out.known_at(known_at);
    ctx.out.event(
        "subledgers",
        vec![
            ("known_at", Json::Int(i128::from(known_at.0))),
            ("subledgers", Json::Arr(rows)),
        ],
        if human.is_empty() {
            "No native subledgers at this recorded coordinate."
        } else {
            &human
        },
    );
    Ok(())
}

fn amount(book: &fa::Book, unit: u32, mantissa: i128) -> Result<Json, Fail> {
    Ok(s(render_amount(
        Amount {
            unit: UnitId(unit),
            mantissa,
        },
        &book.context().units,
    )?))
}

fn net(book: &fa::Book, unit: u32, debits: i128, credits: i128) -> Result<Json, Fail> {
    let value = debits.checked_sub(credits).ok_or_else(|| {
        Fail::Book(fa::BookError::Kernel(fa_journal::KernelError::Corrupt(
            "native subledger net amount exceeds the exact amount domain".into(),
        )))
    })?;
    amount(book, unit, value)
}

fn verify(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let code = code_argument(args, VERIFY)?;
    let date_text = args.require("--as-of", "YYYY-MM-DD")?;
    let as_of = DateDay::parse(date_text)
        .map_err(|error| usage(format!("invalid --as-of: {error:?}"), VERIFY))?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    let report = book.reconcile_native_subledger(&code, as_of, known_at, &cap)??;
    let accounts = book.accounts_at(report.known_at, &cap)??;
    let mut rows = Vec::with_capacity(report.rows.len());
    let mut human = Vec::with_capacity(report.rows.len());
    for row in &report.rows {
        rows.push(obj(vec![
            ("party", s(&row.party_code)),
            ("party_vid", s(format!("{:032x}", row.party.0))),
            (
                "unit",
                s(registered_unit_code(
                    UnitId(row.unit_id),
                    &book.context().units,
                )?),
            ),
            ("debits", amount(&book, row.unit_id, row.debits)?),
            ("credits", amount(&book, row.unit_id, row.credits)?),
            ("net", net(&book, row.unit_id, row.debits, row.credits)?),
            (
                "debits_pending",
                amount(&book, row.unit_id, row.debits_pending)?,
            ),
            (
                "credits_pending",
                amount(&book, row.unit_id, row.credits_pending)?,
            ),
        ]));
        human.push(format!(
            "{:<18} debit {:>18} credit {:>18}",
            row.party_code,
            render_amount(
                Amount {
                    unit: UnitId(row.unit_id),
                    mantissa: row.debits
                },
                &book.context().units
            )?,
            render_amount(
                Amount {
                    unit: UnitId(row.unit_id),
                    mantissa: row.credits
                },
                &book.context().units
            )?,
        ));
    }
    let totals = report
        .totals
        .iter()
        .map(|row| {
            Ok(obj(vec![
                (
                    "unit",
                    s(registered_unit_code(
                        UnitId(row.unit_id),
                        &book.context().units,
                    )?),
                ),
                (
                    "detail_debits",
                    amount(&book, row.unit_id, row.detail_debits)?,
                ),
                (
                    "detail_credits",
                    amount(&book, row.unit_id, row.detail_credits)?,
                ),
                (
                    "detail_debits_pending",
                    amount(&book, row.unit_id, row.detail_debits_pending)?,
                ),
                (
                    "detail_credits_pending",
                    amount(&book, row.unit_id, row.detail_credits_pending)?,
                ),
                (
                    "control_debits",
                    amount(&book, row.unit_id, row.control_debits)?,
                ),
                (
                    "control_credits",
                    amount(&book, row.unit_id, row.control_credits)?,
                ),
                (
                    "control_debits_pending",
                    amount(&book, row.unit_id, row.control_debits_pending)?,
                ),
                (
                    "control_credits_pending",
                    amount(&book, row.unit_id, row.control_credits_pending)?,
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    ctx.out.at_book(&book)?;
    ctx.out.known_at(report.known_at);
    ctx.out.effective(format!("through:{as_of}"));
    human.push(format!(
        "{}: party detail {} control-account posted and pending amounts at sequence {} through {as_of}",
        code,
        if report.reconciled { "equals" } else { "does not equal" },
        report.known_at.0,
    ));
    ctx.out.event(
        "subledger_reconciled",
        vec![
            ("subledger", summary(&report.subledger, &accounts)?),
            ("known_at", Json::Int(i128::from(report.known_at.0))),
            ("effective_through", s(as_of.to_string())),
            ("rows", Json::Arr(rows)),
            ("totals", Json::Arr(totals)),
            ("reconciled", Json::Bool(report.reconciled)),
        ],
        &human.join("\n"),
    );
    if !report.reconciled {
        return Err(Fail::Verification {
            message: format!("native subledger {code} does not reconcile with its control account"),
            detail: obj(vec![("subledger", s(&code)), ("known_at", Json::Int(i128::from(report.known_at.0)))]),
            cite: Some("plan §5.6".to_string()),
            fix: Some("Preserve the book and investigate the party-detail/control-account discrepancy at this coordinate.".to_string()),
        });
    }
    Ok(())
}
