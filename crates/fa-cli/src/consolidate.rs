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
    statement_presentation_basis, usage,
};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa consolidate --period FY2026-P03 [--functional] [--as-known-at HEAD|<seq>|<RFC3339>] [--certify] [--certificate-out <new-file>] --book <dir> --json";

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
    let functional = args.switch("--functional");
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
    let (group, functional_unit, certificate) = if certify {
        if requested_utc_ns.is_some() {
            return Err(usage(
                "a consolidation certificate binds a recorded sequence; an instant's TimeEvidence is not part of its format",
                format!(
                    "use --as-known-at {} to certify this consolidation",
                    known_at.map_or_else(|| "HEAD".to_string(), |seq| seq.0.to_string())
                ),
            ));
        }
        let certified = if functional {
            book.certify_functional_consolidation(who, &capability, &period, known_at)??
        } else {
            // Admission precedes loading, and the requested prefix (not merely
            // HEAD) decides whether cold retained native history is required.
            book.prepare_report_history(who, &capability, known_at)??;
            let selection = fa::ReportSelection::Consolidation {
                period: period.clone(),
            };
            book.read_scope(who, &capability)??
                .admit_report(&selection, known_at)??;
            book.certify_report(selection, known_at)??
        };
        match certified.report {
            fa::ReportOutput::Consolidation(group) if !functional => {
                (*group, None, Some(certified.certificate))
            }
            fa::ReportOutput::FunctionalConsolidation(report) if functional => (
                report.group,
                Some(report.base_unit),
                Some(certified.certificate),
            ),
            _ => {
                return Err(Fail::Internal(
                    "consolidation certification returned another report kind".into(),
                ));
            }
        }
    } else if functional {
        let report = book.functional_consolidation(who, &capability, &period, known_at)??;
        (report.group, Some(report.base_unit), None)
    } else {
        (
            book.consolidation(&period, known_at, &capability)??,
            None,
            None,
        )
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
    render_consolidation_basis(&ctx.out, &book, &group, digest.as_deref(), functional_unit)?;
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
    render_consolidation_basis(out, book, group, certificate, None)
}

pub(crate) fn render_functional_consolidation(
    out: &Out,
    book: &Book,
    report: &fa::FunctionalConsolidation,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    render_consolidation_basis(
        out,
        book,
        &report.group,
        certificate,
        Some(report.base_unit),
    )
}

fn render_consolidation_basis(
    out: &Out,
    book: &Book,
    group: &Consolidation,
    certificate: Option<&str>,
    functional_unit: Option<UnitId>,
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
        let (fields, text) =
            statement_presentation_basis(statement, units, functional_unit.is_some())?;
        human.push(text);
        Ok(obj(fields
            .into_iter()
            .map(|(key, value)| match key {
                "scope" => (
                    key,
                    s(if functional_unit.is_some() {
                        "multi-entity-book-functional-consolidated"
                    } else {
                        "multi-entity-book-consolidated"
                    }),
                ),
                _ => (key, value),
            })
            .collect()))
    };
    let balance_sheet = statement(&group.run.balance_sheet)?;
    let income_statement = statement(&group.run.income_statement)?;

    let mut fields = vec![
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
    ];
    // The event declares all three fields (nullable), so native mode carries
    // them too, as its statements do: no shared unit, native amounts.
    match functional_unit {
        Some(base_unit) => fields.extend([
            ("functional", Json::Bool(true)),
            ("base_unit", s(registered_unit_code(base_unit, units)?)),
            ("valuation_basis", s("retained-base-amounts")),
        ]),
        None => fields.extend([
            ("functional", Json::Bool(false)),
            ("base_unit", Json::Null),
            ("valuation_basis", s("native-amounts")),
        ]),
    }
    out.event_with_certificate("consolidation_run", fields, &human.join("\n"), certificate);
    Ok(())
}

// ---------------------------------------------------------------------------
// fa recon (anchor | post | book-to-book) — plan §12.2, FA-INV-13, fa-259c
// ---------------------------------------------------------------------------

const RECON_USAGE: &str = "fa recon <anchor|post|book-to-book> ...";
const RECON_ANCHOR_EXAMPLE: &str = "fa recon anchor (--parent-certificate <hex|file> | --parent-book <dir> [--parent-known-at HEAD|<seq>] | --parent-book-id <32-hex> --parent-known-at <seq>) --book <layer-dir> --json";
const RECON_POST_EXAMPLE: &str = "fa recon post --reason-code <M1-TEMP-DEPRECIATION|M1-PERM-MEALS|...> [--rule-oid <64-hex>] --intent <file|-> [--approval <vid>]... [--dry-run [--plan-out <new-file>]] --book <layer-dir> --json";
const RECON_BRIDGE_EXAMPLE: &str = "fa recon book-to-book (--period <code> | --as-of YYYY-MM-DD) (--parent-certificate <hex|file> | --parent-book <dir> [--parent-known-at HEAD|<seq>]) [--as-known-at HEAD|<seq>|<RFC3339>] --book <layer-dir> --json";

pub(crate) fn recon_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("anchor") => recon_anchor(ctx, args),
        Some("post") => recon_post(ctx, args),
        Some("book-to-book") => recon_book_to_book(ctx, args),
        _ => Err(usage(
            "fa recon requires a subcommand: anchor, post, or book-to-book",
            RECON_USAGE,
        )),
    }
}

fn parse_id128_hex(raw: &str, flag: &str) -> Result<fa_model::Id128, Fail> {
    let trimmed = raw.trim();
    if trimmed.len() != 32 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(usage(
            format!("{flag} `{raw}` must be a 32-character hex book id"),
            RECON_ANCHOR_EXAMPLE,
        ));
    }
    let mut out = [0u8; 16];
    for (idx, chunk) in trimmed.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(chunk).unwrap_or("");
        out[idx] = u8::from_str_radix(s, 16).map_err(|_| {
            usage(
                format!("{flag} `{raw}` must be a 32-character hex book id"),
                RECON_ANCHOR_EXAMPLE,
            )
        })?;
    }
    Ok(fa_model::Id128(out))
}

fn parse_parent_known_at(
    raw: &str,
    head: fgdb_types::CommitSeq,
) -> Result<fgdb_types::CommitSeq, Fail> {
    if raw == "HEAD" {
        return Ok(head);
    }
    let seq = raw.parse::<u64>().map_err(|_| {
        usage(
            format!("--parent-known-at `{raw}` must be HEAD or a positive integer sequence"),
            RECON_BRIDGE_EXAMPLE,
        )
    })?;
    if seq == 0 || seq > head.0 {
        return Err(usage(
            format!(
                "--parent-known-at {seq} is outside the parent book's committed range 1..={}",
                head.0
            ),
            RECON_BRIDGE_EXAMPLE,
        ));
    }
    Ok(fgdb_types::CommitSeq(seq))
}

fn read_parent_certificate(
    files: &crate::cli::Files,
    raw: &str,
) -> Result<(fa::ReportCertificate, fa_registers::TrialBalance), Fail> {
    let trimmed = raw.trim();
    let is_inline_hex = trimmed != "-"
        && trimmed.len() >= 64
        && trimmed.len().is_multiple_of(2)
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit());
    let bytes = if is_inline_hex {
        decode_unlimited_hex(trimmed, "--parent-certificate")?
    } else {
        let raw_bytes = files.read_bytes(trimmed)?;
        if let Ok(as_str) = std::str::from_utf8(&raw_bytes) {
            let clean = as_str.trim();
            if clean.len() >= 64
                && clean.len().is_multiple_of(2)
                && clean.bytes().all(|b| b.is_ascii_hexdigit())
            {
                decode_unlimited_hex(clean, "--parent-certificate")?
            } else {
                raw_bytes
            }
        } else {
            raw_bytes
        }
    };
    let cert = fa::ReportCertificate::decode(&bytes).map_err(Fail::Refusal)?;
    if cert.output_format() != fa::certificate::OUTPUT_FORMAT {
        return Err(usage(
            format!(
                "--parent-certificate carries output format `{}`, expected `{}`",
                cert.output_format(),
                fa::certificate::OUTPUT_FORMAT
            ),
            "certify a native cumulative stock trial balance in the parent book (`fa tb --period <code> --certify --book <parent-dir>`)",
        ));
    }
    let tb = fa_registers::TrialBalance::decode(&cert.output).map_err(|e| {
        usage(
            format!("--parent-certificate trial balance payload failed to decode: {e}"),
            RECON_BRIDGE_EXAMPLE,
        )
    })?;
    Ok((cert, tb))
}

fn decode_unlimited_hex(hex_text: &str, flag: &str) -> Result<Vec<u8>, Fail> {
    if hex_text.is_empty() || !hex_text.len().is_multiple_of(2) {
        return Err(usage(
            format!("{flag} must be even-length hex"),
            RECON_BRIDGE_EXAMPLE,
        ));
    }
    let mut out = Vec::with_capacity(hex_text.len() / 2);
    for pair in hex_text.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(pair).unwrap_or("");
        let byte = u8::from_str_radix(s, 16).map_err(|_| {
            usage(
                format!("{flag} contains non-hex characters"),
                RECON_BRIDGE_EXAMPLE,
            )
        })?;
        out.push(byte);
    }
    Ok(out)
}

fn open_parent_book(
    files: &crate::cli::Files,
    bound_or_daemon: bool,
    raw_dir: &str,
) -> Result<Book, Fail> {
    if bound_or_daemon {
        return Err(usage(
            "--parent-book cannot open an arbitrary host directory in a daemon or launch-bound request",
            "certify the parent book's trial balance (`fa tb --period <code> --certify`) and pass its hex via --parent-certificate",
        ));
    }
    let dir = files.resolve(raw_dir);
    if !crate::lease::Lease::is_book_dir(&dir) {
        return Err(Fail::Environment(format!(
            "--parent-book `{}` is not a FrankenAccounting book directory",
            dir.display()
        )));
    }
    let keys = fa::BookKeys::load(&dir.join("book.keys"))?;
    Ok(Book::open_dir(&dir, keys, fa::Entropy::production())?)
}

fn recon_anchor(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "fa recon anchor takes no extra positional arguments",
            RECON_ANCHOR_EXAMPLE,
        ));
    }
    let bound_or_daemon = ctx.authority().is_some() || ctx.routed_through_daemon();
    let capability = ctx.capability(args, &["schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::require(
            &capability,
            fa_policy::Op::SchemaChange,
            "anchoring an adjustment-layer book",
        )
        .and_then(|()| fa_policy::scope(&capability, book.context().book_id))
        .and_then(|()| fa_policy::admit_direct_write(&capability))
        .and_then(|()| fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None))
        .map_err(|d| Fail::Refusal(fa_journal::policy::refusal(&d)))?;
        book.admit_current(&capability)??;
        Ok(())
    })?;

    let has_cert = args.flag("--parent-certificate").is_some();
    let has_book = args.flag("--parent-book").is_some();
    let has_id = args.flag("--parent-book-id").is_some();
    if usize::from(has_cert) + usize::from(has_book) + usize::from(has_id) != 1 {
        return Err(usage(
            "pass exactly one of --parent-certificate, --parent-book, or --parent-book-id",
            RECON_ANCHOR_EXAMPLE,
        ));
    }

    let (parent_book_id, parent_known_at) =
        if let Some(cert_raw) = args.flag("--parent-certificate") {
            if args.flag("--parent-known-at").is_some() {
                return Err(usage(
                    "--parent-certificate already binds parent_known_at; omit --parent-known-at",
                    RECON_ANCHOR_EXAMPLE,
                ));
            }
            let (cert, _) = read_parent_certificate(&ctx.files, cert_raw)?;
            (cert.book_id, cert.known_at)
        } else if let Some(parent_dir) = args.flag("--parent-book") {
            let parent = open_parent_book(&ctx.files, bound_or_daemon, parent_dir)?;
            let head = parent.head()?;
            let seq = match args.flag("--parent-known-at") {
                Some(raw) => parse_parent_known_at(raw, head)?,
                None => head,
            };
            (parent.context().book_id, seq)
        } else {
            let id_raw = args.require("--parent-book-id", "<32-hex>")?;
            let seq_raw = args.require("--parent-known-at", "<seq>")?;
            let id = parse_id128_hex(id_raw, "--parent-book-id")?;
            let seq = seq_raw.parse::<u64>().map_err(|_| {
                usage(
                    format!("--parent-known-at `{seq_raw}` must be a positive integer sequence"),
                    RECON_ANCHOR_EXAMPLE,
                )
            })?;
            (id, fgdb_types::CommitSeq(seq))
        };

    let anchored = book.anchor_adjustment_layer(&capability, parent_book_id, parent_known_at)??;
    ctx.out.at_book(&book)?;
    let human = format!(
        "anchored book {} as AdjustmentLayer of parent {} at parent_known_at {} (recorded at {}, document {})",
        book.context().book_id.to_hex(),
        anchored.parent_book_id.to_hex(),
        anchored.parent_known_at.0,
        anchored.recorded_at.0,
        hex(&anchored.document_oid.0),
    );
    ctx.out.event(
        "adjustment_layer_anchored",
        vec![
            ("layered_book_id", s(book.context().book_id.to_hex())),
            ("parent_book_id", s(anchored.parent_book_id.to_hex())),
            (
                "parent_known_at",
                Json::Int(i128::from(anchored.parent_known_at.0)),
            ),
            ("document_oid", s(hex(&anchored.document_oid.0))),
            ("doc_commit", s(hex(&anchored.doc_commit))),
            ("recorded_at", Json::Int(i128::from(anchored.recorded_at.0))),
            ("already_recorded", Json::Bool(anchored.already_recorded)),
        ],
        &human,
    );
    Ok(())
}

fn recon_post(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "fa recon post takes no extra positional arguments",
            RECON_POST_EXAMPLE,
        ));
    }
    crate::cli::check_post_planning_options(args)?;
    let reason_raw = args.require("--reason-code", "<M1-...>")?;
    let Some(reason_code) = fa::BookToBookReasonCode::parse(reason_raw) else {
        let valid: Vec<&str> = fa::BookToBookReasonCode::ALL
            .iter()
            .map(|c| c.as_str())
            .collect();
        return Err(usage(
            format!(
                "unknown --reason-code `{reason_raw}`; valid codes: {}",
                valid.join(", ")
            ),
            RECON_POST_EXAMPLE,
        ));
    };
    let rule_version_oid = match args.flag("--rule-oid") {
        Some(raw) => fa_model::Oid(crate::document::hex32(raw, "--rule-oid")?),
        None => fa_model::Oid(fa_model::domain_digest(
            b"fa:book-to-book:manual-rule:v1",
            &[reason_code.as_str().as_bytes()],
        )),
    };
    let intent_path = args.require("--intent", "<file|->")?;
    let text = ctx.files.read_text(intent_path)?;
    let doc = crate::json::parse(&text)
        .map_err(|e| usage(format!("{intent_path}: {e}"), RECON_POST_EXAMPLE))?;
    let who = ctx.principal(args);
    let capability = ctx.capability(args, crate::fx::posting_ops(&doc))?;
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::require(
            &capability,
            fa_policy::Op::Post,
            "posting an adjustment-layer entry",
        )
        .and_then(|()| fa_policy::scope(&capability, book.context().book_id))
        .and_then(|()| fa_policy::admit_direct_write(&capability))
        .map_err(|d| Fail::Refusal(fa_journal::policy::refusal(&d)))?;
        crate::fx::admit_intent_sources(book, &capability, &doc)
    })?;

    let (mut req, class_name) =
        crate::cli::build_recon_post_request(&ctx.out, &mut book, args, &doc, who, capability)?;
    book.attach_book_to_book_tag(&mut req.proposal, reason_code, rule_version_oid)?;

    // Rebind any explicit `--approval <vid>` references to the tagged proposal_digest.
    if !args.flag_all("--approval").is_empty() {
        let digest = req
            .proposal
            .proposal_digest()
            .map_err(|e| Fail::Internal(format!("recon post proposal_digest: {e}")))?;
        let mut approvals = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for raw_app in args.flag_all("--approval") {
            let approval_vid = crate::cli::parse_vid(raw_app, "--approval")?;
            if !seen.insert(approval_vid) {
                return Err(usage("duplicate --approval supplied", RECON_POST_EXAMPLE));
            }
            approvals.push(fa_model::ApprovalRef {
                approval_vid,
                approved_digest: digest,
            });
        }
        req.approvals = approvals;
    }

    if args.switch("--dry-run") {
        let intent = fa::PostIntent::new(req.proposal, req.approvals).map_err(|e| {
            usage(
                format!("cannot plan adjustment entry: {e}"),
                RECON_POST_EXAMPLE,
            )
        })?;
        let plan = book.plan(intent, &req.capability)??;
        return crate::cli::emit_post_plan(
            &ctx.out,
            &book,
            &ctx.files,
            args,
            &plan,
            &req.capability,
        );
    }
    let posted = book.post(req)??;
    ctx.out.at_book(&book)?;
    crate::cli::emit_posted(&ctx.out, posted, &class_name, false, None, None)
}

fn recon_book_to_book(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "fa recon book-to-book takes no extra positional arguments",
            RECON_BRIDGE_EXAMPLE,
        ));
    }
    let period = args.flag("--period").map(str::to_string);
    let as_of = match args.flag("--as-of") {
        Some(raw) => Some(
            fa_time::DateDay::parse(raw)
                .map_err(|e| usage(format!("--as-of `{raw}`: {e:?}"), RECON_BRIDGE_EXAMPLE))?,
        ),
        None => None,
    };
    if period.is_some() == as_of.is_some() {
        return Err(usage(
            "pass exactly one of --period <code> or --as-of YYYY-MM-DD",
            RECON_BRIDGE_EXAMPLE,
        ));
    }
    let has_cert = args.flag("--parent-certificate").is_some();
    let has_parent_book = args.flag("--parent-book").is_some();
    if has_cert == has_parent_book {
        return Err(usage(
            "pass exactly one of --parent-certificate <hex|file> or --parent-book <dir>",
            RECON_BRIDGE_EXAMPLE,
        ));
    }

    let bound_or_daemon = ctx.authority().is_some() || ctx.routed_through_daemon();
    let capability = ctx.capability(args, &["read", "reconcile"])?;
    let book = ctx.books.open_admitted(args, |book| {
        admit_whole_book_read(
            book,
            &capability,
            &[fa_policy::Op::Reconcile],
            "reconciling a book-to-book bridge",
        )
    })?;
    let (known_at, _) = known_at_flag(args, &book, &ctx.out)?;

    let (parent_book_id, parent_known_at, parent_tb) =
        if let Some(cert_raw) = args.flag("--parent-certificate") {
            if args.flag("--parent-known-at").is_some() {
                return Err(usage(
                    "--parent-certificate already binds parent_known_at; omit --parent-known-at",
                    RECON_BRIDGE_EXAMPLE,
                ));
            }
            let (cert, tb) = read_parent_certificate(&ctx.files, cert_raw)?;
            (cert.book_id, cert.known_at, tb)
        } else {
            let parent_dir = args.require("--parent-book", "<dir>")?;
            let parent = open_parent_book(&ctx.files, bound_or_daemon, parent_dir)?;
            let head = parent.head()?;
            let parent_seq = match args.flag("--parent-known-at") {
                Some(raw) => parse_parent_known_at(raw, head)?,
                None => head,
            };
            let tb = if let Some(ref p) = period {
                // Collect cumulative periods through `p` in the parent book's calendar.
                let mut parent_periods: Vec<_> = parent
                    .periods()?
                    .into_iter()
                    .map(|r| (r.start, r.code))
                    .collect();
                parent_periods.sort();
                let Some(pos) = parent_periods.iter().position(|(_, code)| code == p) else {
                    return Err(usage(
                        format!("period `{p}` does not exist in parent book"),
                        RECON_BRIDGE_EXAMPLE,
                    ));
                };
                let through_codes: Vec<String> = parent_periods[..=pos]
                    .iter()
                    .map(|(_, code)| code.clone())
                    .collect();
                parent.trial_balance_at(&through_codes, Some(parent_seq))?
            } else {
                let day = as_of.expect("checked mutual exclusion");
                parent.balance_as_of(day, Some(parent_seq))?
            };
            (parent.context().book_id, parent_seq, tb)
        };

    let recon = book.reconcile_book_to_book(
        &capability,
        parent_book_id,
        parent_known_at,
        &parent_tb,
        period.as_deref(),
        as_of,
        known_at,
    )??;

    let bridge = &recon.bridge;
    ctx.out
        .known_at(fgdb_types::CommitSeq(bridge.layered_known_at));
    let units = &book.context().units;
    let money =
        |unit: u32, mantissa: i128| render_amount(Amount::new(UnitId(unit), mantissa), units);
    let bridge_bytes = bridge
        .canonical_bytes()
        .map_err(|e| Fail::Internal(format!("encode book-to-book bridge: {e}")))?;

    let mut human = vec![format!(
        "book-to-book bridge: parent {} @ {} -> layer {} @ {} through {} (digest {})",
        bridge.parent_book_id.to_hex(),
        bridge.parent_known_at,
        bridge.layered_book_id.to_hex(),
        bridge.layered_known_at,
        recon.effective_through.render(),
        hex(&recon.bridge_digest.0),
    )];

    let mut rows_json = Vec::with_capacity(bridge.rows.len());
    for row in &bridge.rows {
        let p_str = money(row.unit_id, row.parent_net)?;
        let a_str = money(row.unit_id, row.adjustments_net)?;
        let l_str = money(row.unit_id, row.layered_net)?;
        let unit_code = recon
            .unit_codes
            .get(&row.unit_id)
            .cloned()
            .or_else(|| registered_unit_code(UnitId(row.unit_id), units).ok())
            .unwrap_or_else(|| row.unit_id.to_string());
        human.push(format!(
            "  {:<12} ({})  parent {:>16}  + adj {:>16}  = layer {:>16}",
            row.account_code, unit_code, p_str, a_str, l_str
        ));
        let mut exps_json = Vec::with_capacity(row.explanations.len());
        for exp in &row.explanations {
            let d_str = money(row.unit_id, exp.net_delta)?;
            human.push(format!(
                "      [{}] entry {:032x}  delta {:>16}  (permanent={})",
                exp.reason_code.as_str(),
                exp.entry_id,
                d_str,
                exp.reason_code.is_permanent(),
            ));
            exps_json.push(obj(vec![
                ("entry", s(format!("{:032x}", exp.entry_id))),
                ("rule_version_oid", s(hex(&exp.rule_version_oid.0))),
                ("reason_code", s(exp.reason_code.as_str())),
                ("permanent", Json::Bool(exp.reason_code.is_permanent())),
                ("net_delta", s(d_str)),
            ]));
        }
        rows_json.push(obj(vec![
            ("account", s(format!("{:032x}", row.account_id))),
            ("code", s(&row.account_code)),
            ("unit", s(unit_code)),
            ("parent_net", s(p_str)),
            ("adjustments_net", s(a_str)),
            ("layered_net", s(l_str)),
            ("explanations", Json::Arr(exps_json)),
        ]));
    }

    ctx.out.event(
        "book_to_book_reconciled",
        vec![
            ("parent_book_id", s(bridge.parent_book_id.to_hex())),
            (
                "parent_known_at",
                Json::Int(i128::from(bridge.parent_known_at)),
            ),
            ("layered_book_id", s(bridge.layered_book_id.to_hex())),
            (
                "layered_known_at",
                Json::Int(i128::from(bridge.layered_known_at)),
            ),
            ("period", recon.period.as_deref().map_or(Json::Null, s)),
            ("effective_through", s(recon.effective_through.render())),
            ("bridge_digest", s(hex(&recon.bridge_digest.0))),
            ("bytes", s(hex(&bridge_bytes))),
            ("rows", Json::Arr(rows_json)),
        ],
        &human.join("\n"),
    );
    Ok(())
}
