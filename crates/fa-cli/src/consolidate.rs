//! `fa consolidate --period <code> [--as-known-at HEAD|<seq>|<RFC3339>]`
//! (plan §12.3): the consolidated balance sheet and income statement of a
//! multi-entity book's legal entities, with every elimination derived from
//! the journaled `OWNS` edges and the account roles, the noncontrolling
//! interest, and the proof that consolidated equity equals the members'
//! equity plus the eliminations and the NCI. Nothing is posted.
//!
//! It reads every entity's stock, so it is admitted as a whole-book read
//! before anything is observed: a token carrying any scope caveat is
//! refused, never filtered.

use fa::Book;
use fa::consolidation::Consolidation;
use fa_money::{Amount, UnitId};

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, Out, admit_whole_book_read, hex, known_at_flag, registered_unit_code, render_amount,
    statement_presentation, usage,
};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa consolidate --period FY2026-P03 [--as-known-at HEAD|<seq>|<RFC3339>] [--certify] [--certificate-out <new-file>] --book <dir> --json";

pub(crate) fn consolidate_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 1 {
        return Err(usage(
            "fa consolidate takes no positional argument",
            EXAMPLE,
        ));
    }
    if args.flag_all("--period").len() != 1 {
        return Err(usage(
            "--period names the one period to consolidate",
            EXAMPLE,
        ));
    }
    if args.flag_all("--certificate-out").len() > 1 {
        return Err(usage(
            "--certificate-out may be supplied only once",
            EXAMPLE,
        ));
    }
    let period = args.flag("--period").unwrap_or_default().to_string();
    let who = ctx.principal(args);
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let capability = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_whole_book_read(
            book,
            &capability,
            if certify {
                &[fa_policy::Op::Produce]
            } else {
                &[]
            },
            "consolidating the group",
        )
    })?;
    let (known_at, requested_utc_ns) = known_at_flag(args, &book, &ctx.out)?;
    let (group, certificate) = if certify {
        if requested_utc_ns.is_some() {
            return Err(usage(
                "a consolidation certificate binds a recorded sequence; an instant's TimeEvidence is not part of its format",
                format!(
                    "use --as-known-at {} to certify this consolidation",
                    known_at.map_or_else(|| "HEAD".to_string(), |seq| seq.0.to_string())
                ),
            ));
        }
        // Admission precedes loading, and the requested prefix (not merely
        // HEAD) decides whether cold retained native history is required.
        book.prepare_report_history(who, &capability, known_at)??;
        let selection = fa::ReportSelection::Consolidation {
            period: period.clone(),
        };
        book.read_scope(who, &capability)??
            .admit_report(&selection, known_at)??;
        let certified = book.certify_report(selection, known_at)??;
        let fa::ReportOutput::Consolidation(group) = certified.report else {
            return Err(Fail::Internal(
                "consolidation certification returned another report kind".into(),
            ));
        };
        (*group, Some(certified.certificate))
    } else {
        (book.consolidation(&period, known_at, &capability)??, None)
    };
    let retained = certificate
        .as_ref()
        .map(|certificate| {
            crate::notary::retain_report_certificate(
                &mut book,
                &ctx.files,
                args,
                certificate,
                &capability,
            )
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    render_consolidation(&ctx.out, &book, &group, digest.as_deref())?;
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        crate::notary::emit_report_certificate(&ctx.out, args, certificate, &bytes, &retained);
    }
    Ok(())
}

/// The `consolidation_run` event of one consolidation, with its certificate's
/// digest when it is certified; `fa replay` renders a replayed run here too.
pub(crate) fn render_consolidation(
    out: &Out,
    book: &Book,
    group: &Consolidation,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    out.known_at(group.known_at);
    let units = &book.context().units;
    let money =
        |unit: u32, mantissa: i128| render_amount(Amount::new(UnitId(unit), mantissa), units);
    let account_code = |id: u128| {
        group
            .accounts
            .get(&id)
            .map_or_else(|| format!("{id:032x}"), |(code, _)| code.clone())
    };
    let entity_code = |id| group.entity_codes.get(&id).cloned().unwrap_or_default();

    let mut human = vec![format!(
        "consolidation of {} entities for {} through {} at sequence {} (NCI under {}; run {})",
        group.members.len(),
        group.period,
        group.effective_through.render(),
        group.known_at.0,
        group.rounding_law.name(),
        hex(&group.run_digest),
    )];
    let members: Vec<Json> = group
        .members
        .iter()
        .map(|m| {
            human.push(format!(
                "  {:<12} {}{}",
                m.code,
                m.name,
                match (&m.parent, m.ownership_bps) {
                    (Some(parent), Some(bps)) => format!("  (owned {bps} bps by {parent})"),
                    _ => String::new(),
                }
            ));
            obj(vec![
                ("code", s(&m.code)),
                ("name", s(&m.name)),
                ("parent", m.parent.as_ref().map_or(Json::Null, s)),
                (
                    "ownership_bps",
                    m.ownership_bps
                        .map_or(Json::Null, |bps| Json::Int(i128::from(bps))),
                ),
            ])
        })
        .collect();

    let mut render =
        |title: &str, list: &[fa::consolidation::EliminationEntry]| -> Result<Json, Fail> {
            human.push(title.to_string());
            let mut out = Vec::with_capacity(list.len());
            for elimination in list {
                human.push(format!("{}: {}", elimination.code, elimination.description));
                let mut legs = Vec::with_capacity(elimination.legs.len());
                for leg in &elimination.legs {
                    let debits = money(leg.unit_id, leg.debits)?;
                    let credits = money(leg.unit_id, leg.credits)?;
                    human.push(format!(
                        "  {:<12} {:<12} Dr {:>20}  Cr {:>20}",
                        entity_code(leg.entity_id),
                        account_code(leg.account_id),
                        debits,
                        credits
                    ));
                    legs.push(obj(vec![
                        ("entity", s(entity_code(leg.entity_id))),
                        ("account", s(format!("{:032x}", leg.account_id))),
                        ("code", s(account_code(leg.account_id))),
                        ("debits", s(debits)),
                        ("credits", s(credits)),
                    ]));
                }
                out.push(obj(vec![
                    ("code", s(&elimination.code)),
                    ("description", s(&elimination.description)),
                    (
                        "unit",
                        s(registered_unit_code(UnitId(elimination.unit_id), units)?),
                    ),
                    ("legs", Json::Arr(legs)),
                ]));
            }
            Ok(Json::Arr(out))
        };
    let eliminations = render(
        "balance sheet eliminations (from each member's stock):",
        &group.run.eliminations,
    )?;
    let income_eliminations = render(
        "income statement eliminations (from each member's activity in the period):",
        &group.run.income_eliminations,
    )?;

    let mut equity = Vec::with_capacity(group.run.equity_reconciliations.len());
    for eq in &group.run.equity_reconciliations {
        let m = |v| money(eq.unit_id, v);
        human.push(format!(
            "equity: parent {} + subsidiaries {} + eliminations {} + NCI {} = consolidated {} (controlling {})",
            m(eq.parent_total_equity)?,
            m(eq.subsidiaries_total_equity)?,
            m(eq.equity_eliminations)?,
            m(eq.non_controlling_interest_equity)?,
            m(eq.consolidated_total_equity)?,
            m(eq.controlling_interest_equity)?,
        ));
        equity.push(obj(vec![
            ("unit", s(registered_unit_code(UnitId(eq.unit_id), units)?)),
            ("parent_total_equity", s(m(eq.parent_total_equity)?)),
            (
                "subsidiaries_total_equity",
                s(m(eq.subsidiaries_total_equity)?),
            ),
            ("equity_eliminations", s(m(eq.equity_eliminations)?)),
            (
                "non_controlling_interest_equity",
                s(m(eq.non_controlling_interest_equity)?),
            ),
            (
                "controlling_interest_equity",
                s(m(eq.controlling_interest_equity)?),
            ),
            (
                "consolidated_total_equity",
                s(m(eq.consolidated_total_equity)?),
            ),
        ]));
    }

    let mut statement = |statement: &fa::Statement| -> Result<Json, Fail> {
        let (fields, text) = statement_presentation(statement, units)?;
        human.push(text);
        Ok(obj(fields
            .into_iter()
            .map(|(key, value)| match key {
                "scope" => (key, s("multi-entity-book-consolidated")),
                _ => (key, value),
            })
            .collect()))
    };
    let balance_sheet = statement(&group.run.balance_sheet)?;
    let income_statement = statement(&group.run.income_statement)?;

    out.event_with_certificate(
        "consolidation_run",
        vec![
            ("period", s(&group.period)),
            ("known_at", Json::Int(i128::from(group.known_at.0))),
            ("effective_through", s(group.effective_through.render())),
            ("rounding_law", s(group.rounding_law.name())),
            ("run_digest", s(hex(&group.run_digest))),
            ("members", Json::Arr(members)),
            ("eliminations", eliminations),
            ("income_eliminations", income_eliminations),
            ("equity", Json::Arr(equity)),
            ("balance_sheet", balance_sheet),
            ("income_statement", income_statement),
        ],
        &human.join("\n"),
        certificate,
    );
    Ok(())
}
