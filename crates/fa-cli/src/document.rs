//! `fa document add` and the intent's evidence citations (plan §9.1–§9.2,
//! bead fa-lp6): the CLI half of Docket intake.
//!
//! A document is recorded once, content-addressed; the `document` event
//! prints the citation an intent carries. An intent cites documents in its
//! `evidence` list — an oid string, or `{document_oid, doc_commit?, role?}` —
//! and `--evidence <oid>` (repeatable) appends citations. The kernel, not the
//! CLI, decides whether a citation names a held document under its exact
//! commitment and whether the class's minimum is met.

use crate::json::{Json, obj, s};
use fa::{BookError, PostIntent};
use fa_journal::custody::CustodyBody;
use fa_journal::evidence::{Document, document_vid, self_sourced};
use fa_journal::redaction::{DocumentRead, ViewChunk};
use fa_model::{
    ApprovalRef, Erasable, EvidenceRef, Oid, Reader, Writer, account_vid, principal_vid,
};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::reason_codes::ReasonCodes;
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::args::{Args, nearest};
use crate::cli::{
    Ctx, Fail, build_proposal_from_intent, hex, parse_json, read_plan_bytes, unhandled, usage,
    write_post_plan,
};
use crate::proof::write_new;

const ADD_EXAMPLE: &str = "fa document add invoice.pdf --kind Invoice --mime application/pdf --grade HumanUpload --book <dir> --json";
const EVIDENCE_EXAMPLE: &str = r#""evidence": ["<document oid hex>"] or [{"document_oid": "<hex>", "doc_commit": "<hex>", "role": "Source"}], or --evidence <oid>"#;
/// The role a bare oid citation takes.
const DEFAULT_ROLE: &str = "Source";
const HOLD_PLAN_DOMAIN: &[u8; 20] = b"fa:hold-release-plan";
const HOLD_PLAN_VERSION: u16 = 1;

fn policy() -> Result<EvidencePolicy, Fail> {
    EvidencePolicy::embedded()
        .map_err(|e| Fail::Internal(format!("the embedded evidence policy: {e}")))
}

pub(crate) fn hex32(text: &str, what: &str) -> Result<[u8; 32], Fail> {
    let text = text.strip_prefix("D:").unwrap_or(text);
    let bad = || {
        usage(
            format!("{what}: `{text}` is not 64 hex digits"),
            "copy the value `fa document add --json` printed",
        )
    };
    if text.len() != 64 || !text.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn parse_vid_arg(text: &str, what: &str) -> Result<VId, Fail> {
    let text = text
        .strip_prefix("E:")
        .or_else(|| text.strip_prefix("H:"))
        .or_else(|| text.strip_prefix("A:"))
        .unwrap_or(text);
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(usage(
            format!("{what}: `{text}` is not a 32-hex vid"),
            "pass a 32-hex vertex id",
        ));
    }
    u128::from_str_radix(text, 16).map(VId).map_err(|_| {
        usage(
            format!("{what}: `{text}` is not a 32-hex vid"),
            "pass a 32-hex vertex id",
        )
    })
}

fn parse_subject_vid(text: &str, what: &str) -> Result<VId, Fail> {
    let stripped = text.strip_prefix("D:").unwrap_or(text);
    if stripped.len() == 64 && stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
        let oid = Oid(hex32(stripped, what)?);
        return Ok(document_vid(&oid));
    }
    parse_vid_arg(text, what)
}

fn parse_principal_or_vid(text: &str) -> VId {
    if text.len() == 32
        && text.bytes().all(|b| b.is_ascii_hexdigit())
        && let Ok(raw) = u128::from_str_radix(text, 16)
    {
        return VId(raw);
    }
    principal_vid(text)
}

/// A citation's role as written: a registered name, or its integer tag.
enum Role {
    Name(String),
    Tag(i128),
}

fn role_list(policy: &EvidencePolicy) -> String {
    let roles: Vec<String> = policy
        .roles
        .iter()
        .map(|r| format!("{} ({})", r.name, r.tag))
        .collect();
    format!("role: one of {}", roles.join(", "))
}

fn named(what: &str, given: &str, names: &[&str]) -> Fail {
    usage(
        format!("unknown {what} `{given}`"),
        match nearest(given, names) {
            Some(n) => format!("did you mean `{n}`? ({})", names.join(", ")),
            None => format!("one of: {}", names.join(", ")),
        },
    )
}

/// `fa document <add|read|redact|disclose|custody|erase|hold|attest|import> ...`.
pub(crate) fn document_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    // Dispatch has already refused a subcommand verbs.toml does not register.
    match args.positional.get(1).map(String::as_str) {
        Some("add") => add(ctx, args),
        Some("read") => read_doc(ctx, args),
        Some("redact") => redact_doc(ctx, args),
        Some("disclose") => disclose_doc(ctx, args),
        Some("custody") => custody_doc(ctx, args),
        Some("erase") => erase_doc(ctx, args),
        Some("hold") => hold_doc(ctx, args),
        Some("attest") => attest_doc(ctx, args),
        Some("import") => import_doc(ctx, args),
        Some("list") => list_docs(ctx, args),
        None => Err(usage("`fa document` needs a subcommand", ADD_EXAMPLE)),
        other => Err(unhandled("document", other)),
    }
}

/// `fa document list [--kind <Kind>] [--as-known-at]`: the documents the
/// book holds, as public metadata (plan §9.6: kind, media type, grade, size
/// and commitment stay visible; the bytes need `fa document read`).
fn list_docs(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "document list takes no argument",
            "fa document list [--kind BankStatement] --json",
        ));
    }
    let policy = policy()?;
    let kind = match args.flag("--kind") {
        Some(name) => Some(
            policy
                .kind_by_name(name)
                .ok_or_else(|| {
                    let names: Vec<&str> = policy.kinds.iter().map(|k| k.name.as_str()).collect();
                    named("document kind", name, &names)
                })?
                .tag,
        ),
        None => None,
    };
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, _) = crate::cli::known_at_flag(args, &book, &ctx.out)?;
    let documents: Vec<_> = book
        .documents(known_at)?
        .into_iter()
        .filter(|d| kind.is_none_or(|k| d.kind == k))
        .collect();
    let rows: Vec<Json> = documents
        .iter()
        .map(|d| {
            obj(vec![
                ("oid", s(hex(&d.oid.0))),
                (
                    "kind",
                    s(policy
                        .kind_by_tag(d.kind)
                        .map_or_else(|| d.kind.to_string(), |k| k.name.clone())),
                ),
                ("mime", s(&d.mime)),
                (
                    "grade",
                    s(policy
                        .grade_by_tag(d.grade)
                        .map_or_else(|| d.grade.to_string(), |g| g.name.clone())),
                ),
                ("size", Json::Int(i128::from(d.size))),
                ("doc_commit", s(hex(&d.doc_commit))),
                ("recorded_at", Json::Int(i128::from(d.recorded_at.0))),
            ])
        })
        .collect();
    let human: Vec<String> = documents
        .iter()
        .map(|d| format!("{} {:>8} bytes  {}", hex(&d.oid.0), d.size, d.mime))
        .collect();
    ctx.out.at_book(&book)?;
    if let Some(seq) = known_at {
        ctx.out.known_at(seq);
    }
    ctx.out.event(
        "documents",
        vec![
            ("kind", args.flag("--kind").map_or(Json::Null, s)),
            ("count", Json::Int(rows.len() as i128)),
            ("documents", Json::Arr(rows)),
        ],
        &human.join("\n"),
    );
    Ok(())
}

fn add(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let path = args.positional.get(2).ok_or_else(|| {
        usage(
            "`fa document add` needs a file (or - for stdin)",
            ADD_EXAMPLE,
        )
    })?;
    let policy = policy()?;
    let kind_name = args.flag("--kind").unwrap_or("Other");
    let kind = policy.kind_by_name(kind_name).ok_or_else(|| {
        let names: Vec<&str> = policy.kinds.iter().map(|k| k.name.as_str()).collect();
        named("document kind", kind_name, &names)
    })?;
    let explicit_grade = match args.flag("--grade") {
        Some(grade_name) => Some(policy.grade_by_name(grade_name).ok_or_else(|| {
            let names: Vec<&str> = policy.grades.iter().map(|g| g.name.as_str()).collect();
            named("provenance grade", grade_name, &names)
        })?),
        None => None,
    };
    let mime = args.flag("--mime").unwrap_or("application/octet-stream");
    let retrieved_by = ctx.principal(args);
    let authority = ctx.authority().cloned();
    let mut book = ctx.books.open(args)?;
    if let Some(authority) = &authority {
        book.preflight_intake(authority.capability(), fa::IntakeAction::Upload)??;
    }
    crate::intake_provenance::check_mime(&policy, mime)?;
    let bytes = crate::intake::read_document(&ctx.files, path)?;
    let added = if let Some(authority) = &authority {
        book.upload_document(
            authority.capability(),
            fa_journal::UploadRequest {
                kind: kind.tag,
                mime: mime.to_string(),
                bytes,
                asserted_grade: explicit_grade.map(|g| g.tag),
            },
        )??
    } else {
        // An agent is the primary operator: absent a declaration, the honest
        // default is the self-sourced grade, never a human's.
        let grade = match explicit_grade {
            Some(g) => g,
            None => policy
                .grade_by_name("AgentUpload")
                .ok_or_else(|| Fail::Internal("missing AgentUpload grade".into()))?,
        };
        let doc = Document {
            book_id: book.context().book_id,
            kind: kind.tag,
            mime: mime.to_string(),
            grade: grade.tag,
            retrieved_by,
            bytes,
        };
        book.add_document(&doc)??
    };
    out.at_book(&book)?;
    // On a repeat intake the book's record stands: report its kind and grade.
    let kind_out = policy
        .kind_by_tag(added.kind)
        .map_or_else(|| added.kind.to_string(), |k| k.name.clone());
    let grade_out = policy
        .grade_by_tag(added.grade)
        .map_or_else(|| added.grade.to_string(), |g| g.name.clone());
    let oid = hex(&added.oid.0);
    let commit = hex(&added.doc_commit);
    let self_sourced = self_sourced(&policy, added.grade);
    out.event(
        "document",
        vec![
            ("oid", s(&oid)),
            ("doc_commit", s(&commit)),
            ("kind", s(&kind_out)),
            ("grade", s(&grade_out)),
            ("self_sourced", Json::Bool(self_sourced)),
            ("size", Json::Int(i128::from(added.size))),
            ("recorded_at", Json::Int(i128::from(added.recorded_at.0))),
            ("already_recorded", Json::Bool(added.already_recorded)),
            (
                "evidence",
                obj(vec![
                    ("document_oid", s(&oid)),
                    ("doc_commit", s(&commit)),
                    ("role", s(DEFAULT_ROLE)),
                ]),
            ),
        ],
        &format!(
            "{} document {oid} ({kind_out}, {grade_out}{}, {} bytes) at {}; cite it with --evidence {oid}",
            if added.already_recorded {
                "already recorded:"
            } else {
                "recorded"
            },
            if self_sourced { ", self-sourced" } else { "" },
            added.size,
            added.recorded_at.0
        ),
    );
    Ok(())
}

/// The intent's `evidence` list plus every `--evidence <oid>`, as the sorted,
/// duplicate-free citations the payload requires. A citation without
/// `doc_commit` (absent or null) takes the commitment of the document the
/// book holds at that oid; an oid the book does not hold is passed through
/// for the kernel to refuse with its own code. A `role` is a registered
/// role name or its integer tag (the form `fa explain` prints), so a copied
/// citation keeps its role; any other value is a usage error, never a
/// silent substitution (review D3).
pub(crate) fn parse_evidence(
    intent: &Json,
    args: &Args,
    book: &mut fa::book::Book,
) -> Result<Vec<EvidenceRef>, Fail> {
    let policy = policy()?;
    let mut cited: Vec<(String, Option<String>, Role)> = Vec::new();
    if let Some(list) = intent.get("evidence") {
        let items = list
            .as_arr()
            .ok_or_else(|| usage("`evidence` must be a list", EVIDENCE_EXAMPLE))?;
        for (i, item) in items.iter().enumerate() {
            match item {
                Json::Str(oid) => cited.push((oid.clone(), None, Role::Name(DEFAULT_ROLE.into()))),
                Json::Obj(_) => {
                    let oid = item
                        .get("document_oid")
                        .and_then(Json::as_str)
                        .ok_or_else(|| {
                            usage(
                                format!("evidence[{i}]: `document_oid` must be a string"),
                                EVIDENCE_EXAMPLE,
                            )
                        })?;
                    let commit = match item.get("doc_commit") {
                        None | Some(Json::Null) => None,
                        Some(Json::Str(h)) => Some(h.clone()),
                        Some(_) => {
                            return Err(usage(
                                format!("evidence[{i}]: `doc_commit` must be a hex string"),
                                EVIDENCE_EXAMPLE,
                            ));
                        }
                    };
                    let role = match item.get("role") {
                        None | Some(Json::Null) => Role::Name(DEFAULT_ROLE.into()),
                        Some(Json::Str(name)) => Role::Name(name.clone()),
                        Some(Json::Int(tag)) => Role::Tag(*tag),
                        Some(_) => {
                            return Err(usage(
                                format!("evidence[{i}]: `role` must be a role name or its tag"),
                                role_list(&policy),
                            ));
                        }
                    };
                    cited.push((oid.to_string(), commit, role));
                }
                _ => {
                    return Err(usage(
                        format!("evidence[{i}] is neither an oid string nor a citation object"),
                        EVIDENCE_EXAMPLE,
                    ));
                }
            }
        }
    }
    for raw in args.flag_all("--evidence") {
        let stripped = raw.strip_prefix("D:").unwrap_or(raw);
        let (oid, role) = match stripped.split_once(':') {
            Some((oid, r)) => (oid, Role::Name(r.to_string())),
            None => (stripped, Role::Name(DEFAULT_ROLE.into())),
        };
        cited.push((oid.to_string(), None, role));
    }
    let mut refs = Vec::with_capacity(cited.len());
    for (oid_hex, commit_hex, role) in cited {
        let oid = Oid(hex32(&oid_hex, "evidence document_oid")?);
        let role = match role {
            Role::Name(name) => policy.role_by_name(&name).ok_or_else(|| {
                let names: Vec<&str> = policy.roles.iter().map(|r| r.name.as_str()).collect();
                named("evidence role", &name, &names)
            })?,
            Role::Tag(tag) => u8::try_from(tag)
                .ok()
                .and_then(|t| policy.role_by_tag(t))
                .ok_or_else(|| {
                    usage(
                        format!("evidence role tag {tag} is not registered"),
                        role_list(&policy),
                    )
                })?,
        };
        let doc_commit = match commit_hex {
            Some(h) => hex32(&h, "evidence doc_commit")?,
            None => book.document_commitment(&oid)?.unwrap_or([0u8; 32]),
        };
        refs.push(EvidenceRef {
            document_oid: oid,
            doc_commit,
            role: role.tag,
        });
    }
    refs.sort_unstable();
    if refs.windows(2).any(|w| w[0] == w[1]) {
        return Err(usage(
            "the same document is cited twice in the same role",
            "cite each document once per role",
        ));
    }
    Ok(refs)
}

fn read_doc(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let oid_text = args
        .positional
        .get(2)
        .map(String::as_str)
        .or_else(|| args.flag("--document"))
        .ok_or_else(|| {
            usage(
                "`fa document read` needs a document oid",
                "fa document read <oid> [--out <file>] --book <dir> --json",
            )
        })?;
    let oid = Oid(hex32(oid_text, "document oid")?);
    let out_path = args.flag("--out");
    let policy = policy()?;
    let capability = ctx.capability(args, &["read"])?;
    let mut book = ctx.books.open(args)?;
    let read = book.read_document_for(&capability, &oid)??;
    ctx.out.at_book(&book)?;
    match read {
        DocumentRead::Full(doc) => {
            if let Some(path) = out_path {
                write_new(
                    &ctx.files.resolve(path),
                    path,
                    &doc.bytes,
                    "document",
                    "--out",
                )?;
            }
            let kind_out = policy
                .kind_by_tag(doc.kind)
                .map_or_else(|| doc.kind.to_string(), |k| k.name.clone());
            let grade_out = policy
                .grade_by_tag(doc.grade)
                .map_or_else(|| doc.grade.to_string(), |g| g.name.clone());
            let oid_hex = hex(&oid.0);
            let commit_hex = hex(&doc.doc_commit());
            let bytes_hex = hex(&doc.bytes);
            let text = match std::str::from_utf8(&doc.bytes) {
                Ok(utf8) => Json::Obj(vec![
                    ("untrusted_content".into(), s(utf8)),
                    ("source".into(), s(format!("D:{oid_hex}"))),
                ]),
                Err(_) => Json::Null,
            };
            ctx.out.event(
                "document_read",
                vec![
                    ("oid", s(&oid_hex)),
                    ("doc_commit", s(&commit_hex)),
                    ("view", s("full")),
                    ("kind", s(&kind_out)),
                    ("mime", s(&doc.mime)),
                    ("grade", s(&grade_out)),
                    ("size", Json::Int(doc.bytes.len() as i128)),
                    ("bytes_hex", s(&bytes_hex)),
                    ("text", text),
                    ("disclosed_chunks", Json::Null),
                    ("withheld_chunks", Json::Null),
                    ("view_commit", Json::Null),
                    ("out", out_path.map_or(Json::Null, s)),
                ],
                &format!(
                    "document {oid_hex}: full view ({kind_out}, {grade_out}, {} bytes)",
                    doc.bytes.len()
                ),
            );
        }
        DocumentRead::Redacted(view) => {
            if out_path.is_some() {
                return Err(usage(
                    "--out writes full document bytes; a redacted view carries withheld chunks",
                    "use `fa document disclose <oid> --chunk <n> [--out <file>]` for selective disclosure, or read with `--grant privileged`",
                ));
            }
            let kind_out = policy
                .kind_by_tag(view.kind)
                .map_or_else(|| view.kind.to_string(), |k| k.name.clone());
            let disclosed = view
                .chunks
                .iter()
                .filter(|c| matches!(c, ViewChunk::Disclosed(_)))
                .count();
            let withheld = view.chunks.len().saturating_sub(disclosed);
            let view_commit = view.view_commit().map_err(BookError::Kernel)?;
            let oid_hex = hex(&oid.0);
            ctx.out.event(
                "document_read",
                vec![
                    ("oid", s(&oid_hex)),
                    ("doc_commit", s(hex(&view.doc_commit))),
                    ("view", s("redacted")),
                    ("kind", s(&kind_out)),
                    ("mime", Json::Null),
                    ("grade", Json::Null),
                    ("size", Json::Int(i128::from(view.size))),
                    ("bytes_hex", Json::Null),
                    ("text", Json::Null),
                    ("disclosed_chunks", Json::Int(disclosed as i128)),
                    ("withheld_chunks", Json::Int(withheld as i128)),
                    ("view_commit", s(hex(&view_commit))),
                    ("out", Json::Null),
                ],
                &format!(
                    "document {oid_hex}: redacted view ({kind_out}, {} bytes, {disclosed} disclosed / {withheld} withheld chunks)",
                    view.size
                ),
            );
        }
    }
    Ok(())
}

fn redact_doc(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let oid_text = args
        .positional
        .get(2)
        .map(String::as_str)
        .or_else(|| args.flag("--document"))
        .ok_or_else(|| {
            usage(
                "`fa document redact` needs a document oid",
                "fa document redact <oid> --book <dir> --json",
            )
        })?;
    let oid = Oid(hex32(oid_text, "document oid")?);
    let capability = ctx.capability(args, &["privileged"])?;
    let mut book = ctx.books.open(args)?;
    let derived = book.derive_redacted_view(&capability, &oid)??;
    ctx.out.at_book(&book)?;
    let oid_hex = hex(&oid.0);
    let view_vid = format!("{:032x}", derived.view.0);
    let commit_hex = hex(&derived.view_commit);
    ctx.out.event(
        "redacted_view_derived",
        vec![
            ("oid", s(&oid_hex)),
            ("view_vid", s(&view_vid)),
            ("view_commit", s(&commit_hex)),
            ("contract", Json::Int(i128::from(derived.contract))),
            ("recorded_at", Json::Int(i128::from(derived.recorded_at.0))),
            ("already_recorded", Json::Bool(derived.already_recorded)),
        ],
        &format!(
            "redacted view {view_vid} of document {oid_hex} under contract {} (recorded at {})",
            derived.contract, derived.recorded_at.0
        ),
    );
    Ok(())
}

fn disclose_doc(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let oid_text = args
        .positional
        .get(2)
        .map(String::as_str)
        .or_else(|| args.flag("--document"))
        .ok_or_else(|| {
            usage(
                "`fa document disclose` needs a document oid",
                "fa document disclose <oid> [--chunk <index>]... [--out <file>] --book <dir> --json",
            )
        })?;
    let oid = Oid(hex32(oid_text, "document oid")?);
    let mut chunks = Vec::new();
    for raw in args.flag_all("--chunk") {
        let index: u64 = raw.parse().map_err(|_| {
            usage(
                format!("--chunk `{raw}` must be a non-negative integer chunk index"),
                "--chunk 0",
            )
        })?;
        chunks.push(index);
    }
    let out_path = args.flag("--out");
    let policy = policy()?;
    let capability = ctx.capability(args, &["read", "produce"])?;
    let mut book = ctx.books.open(args)?;
    let artifact = book.export_document_disclosure(&capability, &oid, &chunks)??;
    ctx.out.at_book(&book)?;
    if let Some(path) = out_path {
        write_new(
            &ctx.files.resolve(path),
            path,
            &artifact.bytes,
            "document disclosure",
            "--out",
        )?;
    }
    let oid_hex = hex(&oid.0);
    let kind_out = policy
        .kind_by_tag(artifact.kind)
        .map_or_else(|| artifact.kind.to_string(), |k| k.name.clone());
    let (access_str, contract_val) = match artifact.access {
        fa::DisclosureAccess::Full => ("full", Json::Null),
        fa::DisclosureAccess::Redacted { contract } => {
            ("redacted", Json::Int(i128::from(contract)))
        }
    };
    let req_json: Vec<Json> = artifact
        .requested_chunks
        .iter()
        .map(|c| Json::Int(i128::from(*c)))
        .collect();
    let disclosed_len = artifact.requested_chunks.len();
    ctx.out.event(
        "document_disclosure_exported",
        vec![
            ("oid", s(&oid_hex)),
            ("doc_commit", s(hex(&artifact.doc_commit))),
            ("kind", s(&kind_out)),
            ("document_length", Json::Int(i128::from(artifact.document_length))),
            ("requested_chunks", Json::Arr(req_json)),
            ("access", s(access_str)),
            ("contract", contract_val),
            ("byte_len", Json::Int(artifact.bytes.len() as i128)),
            ("bytes", s(hex(&artifact.bytes))),
            ("out", out_path.map_or(Json::Null, s)),
        ],
        &format!(
            "exported document disclosure for {oid_hex} ({disclosed_len} chunk(s) disclosed, {} bytes)",
            artifact.bytes.len()
        ),
    );
    Ok(())
}

fn custody_doc(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let oid_text = args
        .positional
        .get(2)
        .map(String::as_str)
        .or_else(|| args.flag("--document"))
        .ok_or_else(|| {
            usage(
                "`fa document custody` needs a document oid",
                "fa document custody <oid> [--to <principal>] --book <dir> --json",
            )
        })?;
    let oid = Oid(hex32(oid_text, "document oid")?);
    let oid_hex = hex(&oid.0);
    if let Some(to_text) = args.flag("--to") {
        let to = parse_principal_or_vid(to_text);
        let capability = ctx.capability(args, &["post"])?;
        let mut book = ctx.books.open(args)?;
        let moved = book.transfer_custody(&capability, &oid, to)??;
        ctx.out.at_book(&book)?;
        let event_vid = format!("{:032x}", moved.event.0);
        let to_hex = format!("{:032x}", to.0);
        ctx.out.event(
            "custody_transferred",
            vec![
                ("oid", s(&oid_hex)),
                ("event_vid", s(&event_vid)),
                ("index", Json::Int(i128::from(moved.index))),
                ("to", s(&to_hex)),
                ("recorded_at", Json::Int(i128::from(moved.recorded_at.0))),
            ],
            &format!(
                "transferred custody of document {oid_hex} to {to_hex} (event #{}, recorded at {})",
                moved.index, moved.recorded_at.0
            ),
        );
        return Ok(());
    }
    let book = ctx.books.open(args)?;
    let chain = book.custody_chain(&oid)?;
    ctx.out.at_book(&book)?;
    let mut events = Vec::with_capacity(chain.len());
    for (ev, seq) in &chain {
        let digest = ev.digest().map_err(BookError::Kernel)?;
        let (kind, from) = match &ev.body {
            CustodyBody::Receipt { .. } => ("receipt", Json::Null),
            CustodyBody::Transfer { from, .. } => ("transfer", s(format!("{:032x}", from.0))),
        };
        events.push(obj(vec![
            ("index", Json::Int(i128::from(ev.index))),
            ("kind", s(kind)),
            ("holder", s(format!("{:032x}", ev.holder().0))),
            ("from", from),
            ("digest", s(hex(&digest))),
            ("prev_digest", s(hex(&ev.prev_digest))),
            ("recorded_at", Json::Int(i128::from(seq.0))),
        ]));
    }
    ctx.out.event(
        "custody_chain",
        vec![("oid", s(&oid_hex)), ("events", Json::Arr(events))],
        &format!("document {oid_hex}: {} custody event(s)", chain.len()),
    );
    Ok(())
}

fn erase_doc(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let subject_text = args
        .positional
        .get(2)
        .map(String::as_str)
        .or_else(|| args.flag("--subject"))
        .ok_or_else(|| {
            usage(
                "`fa erase` needs a subject vid or document oid",
                "fa erase <subject_vid_or_oid> --book <dir> --json",
            )
        })?;
    let subject = parse_subject_vid(subject_text, "erase subject")?;
    let capability = ctx.capability(args, &["erase"])?;
    let book = ctx.books.open(args)?;
    let refusal = book.erasure_cut(&capability, subject)?;
    Err(Fail::Refusal(refusal))
}

fn encode_release_plan(plan: &fa_journal::ReleasePlan) -> Result<Vec<u8>, Fail> {
    let mut w = Writer::new();
    w.fixed(HOLD_PLAN_DOMAIN)
        .u16(HOLD_PLAN_VERSION)
        .u128(plan.hold.0)
        .fixed(&plan.authority.0)
        .u128(plan.principal_ref.0)
        .i32(plan.effective_date.0)
        .bytes(&plan.idempotency_key);
    plan.description.encode(&mut w);
    w.finish()
        .map_err(|e| Fail::Internal(format!("release plan encode: {e}")))
}

fn decode_release_plan(bytes: &[u8]) -> Result<fa_journal::ReleasePlan, Fail> {
    let mut r = Reader::new(bytes);
    let plan = (|| -> Result<fa_journal::ReleasePlan, fa_model::DecodeError> {
        let domain: [u8; 20] = r.fixed("hold_plan.domain")?;
        if domain != *HOLD_PLAN_DOMAIN {
            return Err(r.invalid("hold_plan.domain"));
        }
        if r.u16("hold_plan.version")? != HOLD_PLAN_VERSION {
            return Err(r.invalid("hold_plan.version"));
        }
        Ok(fa_journal::ReleasePlan {
            hold: VId(r.u128("hold_plan.hold")?),
            authority: Oid(r.fixed("hold_plan.authority")?),
            principal_ref: VId(r.u128("hold_plan.principal")?),
            effective_date: DateDay(r.i32("hold_plan.date")?),
            idempotency_key: r
                .bytes(fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES, "hold_plan.key")?
                .to_vec(),
            description: Erasable::decode(&mut r, fa_model::limits::MAX_DESCRIPTION_BYTES)?,
        })
    })()
    .and_then(|plan| {
        r.finish()?;
        Ok(plan)
    })
    .map_err(|e| {
        usage(
            format!("invalid legal hold release plan: {e}"),
            "plan first with `fa hold release <hold_vid> --plan-out <file>`",
        )
    })?;
    Ok(plan)
}

fn hold_doc(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(2).map(String::as_str) {
        Some("place") => {
            let authority_text = args.require("--authority", "<authority_document_oid>")?;
            let authority = Oid(hex32(authority_text, "--authority")?);
            let subject_flags = args.flag_all("--subject");
            if subject_flags.is_empty() {
                return Err(usage(
                    "`fa hold place` needs at least one --subject <vid|oid>",
                    "fa hold place --subject <vid> --authority <document_oid> --book <dir> --json",
                ));
            }
            let mut subjects = Vec::with_capacity(subject_flags.len());
            for s_flag in subject_flags {
                subjects.push(parse_subject_vid(s_flag, "--subject")?);
            }
            let date = match args.flag("--effective").or_else(|| args.flag("--date")) {
                Some(d) => DateDay::parse(d).map_err(|e| {
                    usage(
                        format!("effective date `{d}`: {e:?}"),
                        "--effective YYYY-MM-DD",
                    )
                })?,
                None => DateDay(0),
            };
            let description = args.flag("--description").unwrap_or("");
            let key = args
                .flag("--key")
                .map(|k| k.as_bytes().to_vec())
                .unwrap_or_else(|| {
                    let auth_hex = hex(&authority.0);
                    format!("hold:place:{}", &auth_hex[..32]).into_bytes()
                });
            let capability = ctx.capability(args, &["hold"])?;
            let mut book = ctx.books.open(args)?;
            let placed =
                book.place_legal_hold(&capability, subjects, &authority, &key, date, description)??;
            ctx.out.at_book(&book)?;
            let hold_hex = format!("{:032x}", placed.hold.0);
            let subj_json: Vec<Json> = placed
                .subjects
                .iter()
                .map(|v| s(format!("{:032x}", v.0)))
                .collect();
            ctx.out.event(
                "legal_hold_placed",
                vec![
                    ("hold_vid", s(&hold_hex)),
                    ("subjects", Json::Arr(subj_json)),
                    ("authority", s(hex(&authority.0))),
                    ("recorded_at", Json::Int(i128::from(placed.recorded_at.0))),
                    ("already_recorded", Json::Bool(placed.already_recorded)),
                ],
                &format!(
                    "placed legal hold {hold_hex} over {} subject(s) (recorded at {})",
                    placed.subjects.len(),
                    placed.recorded_at.0
                ),
            );
            Ok(())
        }
        Some("release") => {
            let hold_text = args
                .positional
                .get(3)
                .map(String::as_str)
                .or_else(|| args.flag("--hold"))
                .ok_or_else(|| {
                    usage(
                        "`fa hold release` needs a hold vid",
                        "fa hold release <hold_vid> [--plan-out <file> | --plan <file> --approval <vid>] --book <dir> --json",
                    )
                })?;
            let hold = parse_vid_arg(hold_text, "hold vid")?;
            let who = ctx.principal(args);
            let capability = ctx.capability(args, &["hold"])?;
            let date = match args.flag("--effective").or_else(|| args.flag("--date")) {
                Some(d) => DateDay::parse(d).map_err(|e| {
                    usage(
                        format!("effective date `{d}`: {e:?}"),
                        "--effective YYYY-MM-DD",
                    )
                })?,
                None => DateDay(0),
            };
            let key = args
                .flag("--key")
                .map(|k| k.as_bytes().to_vec())
                .unwrap_or_else(|| format!("hold:release:{:032x}", hold.0).into_bytes());
            let approval_flags = args.flag_all("--approval");
            let mut book = ctx.books.open(args)?;
            if args.switch("--dry-run") || args.flag("--plan-out").is_some() {
                if args.flag("--plan").is_some() || !approval_flags.is_empty() {
                    return Err(usage(
                        "--plan-out / --dry-run prepares a release plan and commits nothing",
                        "commit with `fa hold release <hold_vid> --plan <file> --approval <vid>`",
                    ));
                }
                let plan = book.plan_legal_hold_release(hold, who, date, &key)??;
                let digest = book.legal_hold_release_digest(&plan)?;
                let bytes = encode_release_plan(&plan)?;
                let plan_out = args.flag("--plan-out");
                if let Some(path) = plan_out {
                    write_post_plan(&ctx.files, path, &bytes)?;
                }
                ctx.out.at_book(&book)?;
                let hold_hex = format!("{:032x}", hold.0);
                let digest_hex = hex(&digest);
                ctx.out.event(
                    "legal_hold_release_planned",
                    vec![
                        ("hold_vid", s(&hold_hex)),
                        ("proposal_digest", s(&digest_hex)),
                        ("bytes", s(hex(&bytes))),
                        ("plan", plan_out.map_or(Json::Null, s)),
                    ],
                    &format!(
                        "planned release of legal hold {hold_hex}; approvals bind proposal {digest_hex}"
                    ),
                );
                return Ok(());
            }
            let plan = match args.flag("--plan") {
                Some(path) => {
                    let bytes =
                        read_plan_bytes(&ctx.files, path, HOLD_PLAN_DOMAIN, "legal hold release")?;
                    let decoded = decode_release_plan(&bytes)?;
                    if decoded.hold != hold {
                        return Err(usage(
                            format!(
                                "{path} plans release of hold {:032x}, not {:032x}",
                                decoded.hold.0, hold.0
                            ),
                            "pass the release plan written for this hold",
                        ));
                    }
                    decoded
                }
                None => book.plan_legal_hold_release(hold, who, date, &key)??,
            };
            let digest = book.legal_hold_release_digest(&plan)?;
            let approvals = approval_flags
                .iter()
                .map(|v| {
                    Ok(ApprovalRef {
                        approval_vid: parse_vid_arg(v, "--approval")?,
                        approved_digest: digest,
                    })
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            let released = book.release_legal_hold(&plan, &capability, &approvals)??;
            ctx.out.at_book(&book)?;
            let release_hex = format!("{:032x}", released.release.0);
            let hold_hex = format!("{:032x}", released.hold.0);
            ctx.out.event(
                "legal_hold_released",
                vec![
                    ("release_vid", s(&release_hex)),
                    ("hold_vid", s(&hold_hex)),
                    ("recorded_at", Json::Int(i128::from(released.recorded_at.0))),
                    ("already_recorded", Json::Bool(released.already_recorded)),
                ],
                &format!(
                    "released legal hold {hold_hex} (release entry {release_hex}, recorded at {})",
                    released.recorded_at.0
                ),
            );
            Ok(())
        }
        Some("show") => {
            let hold_text = args
                .positional
                .get(3)
                .map(String::as_str)
                .or_else(|| args.flag("--hold"))
                .ok_or_else(|| {
                    usage(
                        "`fa hold show` needs a hold vid",
                        "fa hold show <hold_vid> --book <dir> --json",
                    )
                })?;
            let hold_vid = parse_vid_arg(hold_text, "hold vid")?;
            let book = ctx.books.open(args)?;
            let Some(hold) = book.legal_hold(hold_vid)? else {
                return Err(usage(
                    format!("no legal hold {:032x} in this book", hold_vid.0),
                    "pass the hold_vid printed by `fa hold place --json`",
                ));
            };
            ctx.out.at_book(&book)?;
            let hold_hex = format!("{:032x}", hold.hold.0);
            let subj_json: Vec<Json> = hold
                .subjects
                .iter()
                .map(|v| s(format!("{:032x}", v.0)))
                .collect();
            let (release_vid, released_at) = match hold.released {
                Some((vid, seq)) => (s(format!("{:032x}", vid.0)), Json::Int(i128::from(seq.0))),
                None => (Json::Null, Json::Null),
            };
            ctx.out.event(
                "legal_hold",
                vec![
                    ("hold_vid", s(&hold_hex)),
                    ("authority", s(hex(&hold.authority.0))),
                    ("subjects", Json::Arr(subj_json)),
                    ("issued_by", s(format!("{:032x}", hold.issued_by.0))),
                    ("placed_at", Json::Int(i128::from(hold.placed_at.0))),
                    ("active", Json::Bool(hold.released.is_none())),
                    ("release_vid", release_vid),
                    ("released_at", released_at),
                ],
                &format!(
                    "legal hold {hold_hex}: {} ({} subject(s), placed at {})",
                    if hold.released.is_none() {
                        "active"
                    } else {
                        "released"
                    },
                    hold.subjects.len(),
                    hold.placed_at.0
                ),
            );
            Ok(())
        }
        Some("list") => {
            // The holds active on one subject (an entry, a document or any
            // held vertex), ascending: what blocks its erasure or release.
            const FIX: &str = "fa document hold list --subject <vid|oid> --book <dir> --json";
            let subject = match args.flag_all("--subject").as_slice() {
                [one] => parse_subject_vid(one, "--subject")?,
                _ => {
                    return Err(usage(
                        "`fa document hold list` takes exactly one --subject <vid|oid>",
                        FIX,
                    ));
                }
            };
            if args.positional.len() != 3 {
                return Err(usage("`fa document hold list` takes no argument", FIX));
            }
            let who = ctx.principal(args);
            let cap = ctx.capability(args, &["read"])?;
            let book = ctx
                .books
                .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
            let holds = book.legal_holds_on(subject)?;
            ctx.out.at_book(&book)?;
            ctx.out.event(
                "legal_holds",
                vec![
                    ("subject", s(format!("{:032x}", subject.0))),
                    (
                        "holds",
                        Json::Arr(holds.iter().map(|v| s(format!("{:032x}", v.0))).collect()),
                    ),
                ],
                &if holds.is_empty() {
                    format!("no active legal hold on {:032x}", subject.0)
                } else {
                    format!(
                        "{} active legal hold(s) on {:032x}: {}",
                        holds.len(),
                        subject.0,
                        holds
                            .iter()
                            .map(|v| format!("{:032x}", v.0))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
            );
            Ok(())
        }
        other => Err(usage(
            format!(
                "`fa hold` needs `place`, `release`, `show` or `list`{}",
                other.map_or_else(String::new, |o| format!(" (got `{o}`)"))
            ),
            "fa hold place|release|show|list ...",
        )),
    }
}

fn attest_doc(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(2).map(String::as_str) {
        Some("review") => {
            let oid_text = args
                .positional
                .get(3)
                .map(String::as_str)
                .or_else(|| args.flag("--document"))
                .ok_or_else(|| {
                    usage(
                        "`fa attest review` needs a document oid",
                        "fa attest review <oid> [--against <oid>]... --book <dir> --json",
                    )
                })?;
            let document = Oid(hex32(oid_text, "document oid")?);
            let mut against = Vec::new();
            for a in args.flag_all("--against") {
                against.push(Oid(hex32(a, "--against")?));
            }
            against.sort();
            let capability = ctx.capability(args, &["approve"])?;
            let mut book = ctx.books.open(args)?;
            let attested = book.record_review(&capability, &document, against)??;
            ctx.out.at_book(&book)?;
            let vid_hex = format!("{:032x}", attested.vid.0);
            let subj_hex = hex(&document.0);
            ctx.out.event(
                "attestation_recorded",
                vec![
                    ("attestation_vid", s(&vid_hex)),
                    ("claim", s("Reviewed")),
                    ("subject", s(&subj_hex)),
                    ("signed_digest", s(hex(&attested.signed_digest))),
                    ("recorded_at", Json::Int(i128::from(attested.recorded_at.0))),
                    ("already_recorded", Json::Bool(attested.already_recorded)),
                    ("holds", Json::Null),
                ],
                &format!(
                    "recorded Reviewed attestation {vid_hex} for document {subj_hex} at {}",
                    attested.recorded_at.0
                ),
            );
            Ok(())
        }
        Some("manual") => {
            let intent_path = args.require("--intent", "entry.json (or - for stdin)")?;
            let reason_text = args.require("--reason", "NoDocumentIssued")?;
            let statement = args.require(
                "--statement",
                "\"bank fee shown only on statement; no separate invoice issued\"",
            )?;
            let reasons = ReasonCodes::embedded()
                .map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
            let reason_code = if let Ok(code) = reason_text.parse::<u16>() {
                code
            } else {
                reasons
                    .rows
                    .iter()
                    .find(|r| r.scope == "manual_assertion" && r.name == reason_text)
                    .map(|r| r.code)
                    .ok_or_else(|| {
                        usage(
                            format!("manual assertion reason `{reason_text}` is not registered"),
                            format!("one of: {}", reasons.listing("manual_assertion")),
                        )
                    })?
            };
            let who = ctx.principal(args);
            let capability = ctx.capability(args, &["post"])?;
            let text = ctx.files.read_text(intent_path)?;
            let doc = parse_json(intent_path, &text)?;
            let mut book = ctx.books.open(args)?;
            let proposal = build_proposal_from_intent(
                &ctx.out,
                &mut book,
                args,
                &doc,
                who,
                capability.clone(),
            )?;
            let proposal_digest = proposal
                .proposal_digest()
                .map_err(fa_journal::KernelError::Model)
                .map_err(BookError::Kernel)?;
            let attested =
                book.record_manual_assertion(&capability, &proposal, reason_code, statement)??;
            if let Some(plan_out) = args.flag("--plan-out") {
                let intent = PostIntent::new(proposal, Vec::new()).map_err(|e| {
                    usage(
                        format!("cannot plan this entry: {e}"),
                        "check the entry intent",
                    )
                })?;
                let plan = book.plan(intent, &capability)??;
                let bytes = plan
                    .canonical_bytes()
                    .map_err(|e| Fail::Internal(format!("plan encode: {e}")))?;
                write_post_plan(&ctx.files, plan_out, &bytes)?;
            }
            ctx.out.at_book(&book)?;
            let vid_hex = format!("{:032x}", attested.vid.0);
            let subj_hex = hex(&proposal_digest);
            ctx.out.event(
                "attestation_recorded",
                vec![
                    ("attestation_vid", s(&vid_hex)),
                    ("claim", s("ManualAssertion")),
                    ("subject", s(&subj_hex)),
                    ("signed_digest", s(hex(&attested.signed_digest))),
                    ("recorded_at", Json::Int(i128::from(attested.recorded_at.0))),
                    ("already_recorded", Json::Bool(attested.already_recorded)),
                    ("holds", Json::Null),
                ],
                &format!(
                    "recorded ManualAssertion attestation {vid_hex} for proposal {subj_hex} at {}",
                    attested.recorded_at.0
                ),
            );
            Ok(())
        }
        Some("register-equals") => {
            if let Some(vid_text) = args
                .positional
                .get(3)
                .map(String::as_str)
                .or_else(|| args.flag("--attestation"))
            {
                let vid = parse_vid_arg(vid_text, "attestation vid")?;
                let book = ctx.books.open(args)?;
                let Some(holds) = book.assertion_holds(vid)? else {
                    return Err(usage(
                        format!("no RegisterEquals attestation {:032x} in this book", vid.0),
                        "pass the attestation_vid printed by `fa attest register-equals --account ...`",
                    ));
                };
                ctx.out.at_book(&book)?;
                let vid_hex = format!("{:032x}", vid.0);
                ctx.out.event(
                    "attestation_recorded",
                    vec![
                        ("attestation_vid", s(&vid_hex)),
                        ("claim", s("RegisterEquals")),
                        ("subject", s(&vid_hex)),
                        ("signed_digest", Json::Null),
                        ("recorded_at", Json::Int(i128::from(book.head()?.0))),
                        ("already_recorded", Json::Bool(true)),
                        ("holds", Json::Bool(holds)),
                    ],
                    &format!("RegisterEquals attestation {vid_hex}: holds = {holds}"),
                );
                return Ok(());
            }
            let account_code = args.require("--account", "1000")?;
            let period = args.require("--period", "FY2026-P03")?.to_string();
            let entity = args.flag("--entity").map(str::to_string);
            let known_at = match args.flag("--as-known-at") {
                None | Some("HEAD") => None,
                Some(raw) => Some(CommitSeq(raw.parse::<u64>().map_err(|_| {
                    usage(
                        format!("--as-known-at `{raw}` must be a CommitSeq or HEAD"),
                        "--as-known-at HEAD",
                    )
                })?)),
            };
            let mut evidence = Vec::new();
            for e in args.flag_all("--evidence") {
                evidence.push(Oid(hex32(e, "--evidence")?));
            }
            evidence.sort();
            let capability = ctx.capability(args, &["reconcile"])?;
            let mut book = ctx.books.open(args)?;
            let unit_id = match args.flag("--unit") {
                Some(u) => {
                    book.context()
                        .units
                        .lookup(u)
                        .ok_or_else(|| usage(format!("unknown unit `{u}`"), "--unit USD"))?
                        .0
                }
                None => book.spec()?.base_unit.0,
            };
            let key = fa::EntityCellKey {
                account: account_vid(book.context().book_id, account_code),
                unit_id,
                period,
                entity,
            };
            let claim = book.evaluate_register_equals(&key, known_at)?;
            let attested = book.record_register_equals(&capability, &claim, evidence)??;
            let holds = book.assertion_holds(attested.vid)?.unwrap_or(true);
            ctx.out.at_book(&book)?;
            let vid_hex = format!("{:032x}", attested.vid.0);
            let cell_hex = hex(&claim.fold_digest);
            ctx.out.event(
                "attestation_recorded",
                vec![
                    ("attestation_vid", s(&vid_hex)),
                    ("claim", s("RegisterEquals")),
                    ("subject", s(&cell_hex)),
                    ("signed_digest", s(hex(&attested.signed_digest))),
                    ("recorded_at", Json::Int(i128::from(attested.recorded_at.0))),
                    ("already_recorded", Json::Bool(attested.already_recorded)),
                    ("holds", Json::Bool(holds)),
                ],
                &format!(
                    "recorded RegisterEquals attestation {vid_hex} at {} (holds = {holds})",
                    attested.recorded_at.0
                ),
            );
            Ok(())
        }
        other => Err(usage(
            format!(
                "`fa attest` needs `review`, `manual`, or `register-equals`{}",
                other.map_or_else(String::new, |o| format!(" (got `{o}`)"))
            ),
            "fa attest review|manual|register-equals ...",
        )),
    }
}

fn parse_intake_source(raw: Option<&str>, who: VId) -> fa_model::IntakeSource {
    match raw {
        None | Some("Connector") | Some("fa-import") => fa_model::IntakeSource::Connector {
            name: "fa-import".to_string(),
            version: "1".to_string(),
        },
        Some("Upload") => fa_model::IntakeSource::Upload { principal: who },
        Some(s) if s.starts_with("Connector:") => {
            let rest = &s["Connector:".len()..];
            let (name, version) = rest.split_once(':').unwrap_or((rest, "1"));
            fa_model::IntakeSource::Connector {
                name: name.to_string(),
                version: version.to_string(),
            }
        }
        Some("Email") => fa_model::IntakeSource::Email {
            message_id: String::new(),
        },
        Some(s) if s.starts_with("Email:") => fa_model::IntakeSource::Email {
            message_id: s["Email:".len()..].to_string(),
        },
        Some("Scan") => fa_model::IntakeSource::Scan {
            device: "scanner".to_string(),
        },
        Some(s) if s.starts_with("Scan:") => fa_model::IntakeSource::Scan {
            device: s["Scan:".len()..].to_string(),
        },
        Some(other) => fa_model::IntakeSource::Connector {
            name: other.to_string(),
            version: "1".to_string(),
        },
    }
}

fn import_doc(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(2).map(String::as_str) {
        Some("run") => {
            let policy = policy()?;
            let kind_name = args.flag("--kind").unwrap_or("Other");
            let kind = policy.kind_by_name(kind_name).ok_or_else(|| {
                let names: Vec<&str> = policy.kinds.iter().map(|k| k.name.as_str()).collect();
                named("document kind", kind_name, &names)
            })?;
            let explicit_grade = match args.flag("--grade") {
                Some(grade_name) => Some(policy.grade_by_name(grade_name).ok_or_else(|| {
                    let names: Vec<&str> = policy.grades.iter().map(|g| g.name.as_str()).collect();
                    named("provenance grade", grade_name, &names)
                })?),
                None => None,
            };
            let mime = args.flag("--mime").unwrap_or("application/octet-stream");
            let date_str = args
                .flag("--date")
                .or_else(|| args.flag("--effective"))
                .unwrap_or("2026-01-01");
            let date = DateDay::parse(date_str).map_err(|e| {
                usage(
                    format!("invalid date `{date_str}`: {e}"),
                    "--date YYYY-MM-DD",
                )
            })?;
            let description = args.flag("--description").unwrap_or("import run");
            let mut paths: Vec<&str> = args.flag_all("--file");
            paths.extend(args.positional.iter().skip(3).map(String::as_str));
            if paths.is_empty() && args.flag("--plan") == Some("-") {
                paths.push("-");
            }
            if paths.is_empty() {
                return Err(usage(
                    "`fa import run` needs at least one --file <path> (or - for stdin)",
                    "fa import run --source Connector --file invoice.pdf --book <dir> --json",
                ));
            }
            crate::intake::validate_documents(&paths)?;
            let who = ctx.principal(args);
            let capability = ctx.capability(args, &["post"])?;
            let (source, grade) = if ctx.authority().is_some() {
                crate::intake_provenance::session_import(
                    &policy,
                    &capability,
                    args.flag("--source"),
                    explicit_grade.map(|grade| grade.tag),
                )?
            } else {
                // The labelled embedded-owner route retains its conservative
                // default and registered source assertions. Bound sessions do
                // not acquire that posture from command-line metadata.
                let grade = match explicit_grade {
                    Some(grade) => grade,
                    None => policy
                        .grade_by_name("AgentUpload")
                        .ok_or_else(|| Fail::Internal("missing AgentUpload grade".into()))?,
                };
                (parse_intake_source(args.flag("--source"), who), grade.tag)
            };
            fa_journal::custody::admit_source(&source)?;
            let mut book = ctx.books.open(args)?;
            book.preflight_intake(&capability, fa::IntakeAction::ImportRun)??;
            crate::intake_provenance::check_mime(&policy, mime)?;
            crate::intake_provenance::check_import_header(args.flag("--key"), description)?;
            let raw_bytes = crate::intake::read_documents(&ctx.files, &paths)?;
            let book_id = book.context().book_id;
            let docs: Vec<Document> = raw_bytes
                .into_iter()
                .map(|bytes| Document {
                    book_id,
                    kind: kind.tag,
                    mime: mime.to_string(),
                    grade,
                    retrieved_by: who,
                    bytes,
                })
                .collect();
            let idempotency_key: Vec<u8> = match args.flag("--key") {
                Some(k) => k.as_bytes().to_vec(),
                None => {
                    let mut oids: Vec<Oid> = docs.iter().map(Document::oid).collect();
                    oids.sort_unstable();
                    fa_journal::import::oids_root(&oids).to_vec()
                }
            };
            let recorded = book.import_run(
                &capability,
                source,
                &idempotency_key,
                date,
                description,
                docs,
            )??;
            ctx.out.at_book(&book)?;
            let run_hex = format!("{:032x}", recorded.receipt.run.0);
            let src_kind = recorded.receipt.source.kind_name();
            let root_hex = hex(&recorded.receipt.oids_root);
            let hash_hex = hex(&recorded.receipt.receipt_hash);
            let rec_arr: Vec<Json> = recorded.recorded.iter().map(|o| s(hex(&o.0))).collect();
            let held_arr: Vec<Json> = recorded.already_held.iter().map(|o| s(hex(&o.0))).collect();
            ctx.out.event(
                "import_recorded",
                vec![
                    ("run_vid", s(&run_hex)),
                    ("source_kind", s(src_kind)),
                    (
                        "document_count",
                        Json::Int(i128::from(recorded.receipt.document_count)),
                    ),
                    (
                        "byte_count",
                        Json::Int(i128::from(recorded.receipt.byte_count)),
                    ),
                    ("oids_root", s(&root_hex)),
                    ("receipt_hash", s(&hash_hex)),
                    ("recorded", Json::Arr(rec_arr)),
                    ("already_held", Json::Arr(held_arr)),
                    (
                        "recorded_at",
                        Json::Int(i128::from(recorded.receipt.recorded_at.0)),
                    ),
                    ("already_recorded", Json::Bool(recorded.already_recorded)),
                ],
                &format!(
                    "import run {run_hex} ({src_kind}, {} docs, {} bytes, receipt {hash_hex}) at {}",
                    recorded.receipt.document_count,
                    recorded.receipt.byte_count,
                    recorded.receipt.recorded_at.0
                ),
            );
            Ok(())
        }
        Some("receipt") => {
            let run_text = args
                .positional
                .get(3)
                .map(String::as_str)
                .or_else(|| args.flag("--run"))
                .ok_or_else(|| {
                    usage(
                        "`fa import receipt` needs a run vid",
                        "fa import receipt <run-vid> [--evidence <oid>]... --book <dir> --json",
                    )
                })?;
            let run_vid = parse_vid_arg(run_text, "import run vid")?;
            let _capability = ctx.capability(args, &["read"])?;
            let cited = args.flag_all("--evidence");
            let mut oids = Vec::with_capacity(cited.len());
            for raw in cited {
                oids.push(Oid(hex32(raw, "--evidence")?));
            }
            let book = ctx.books.open(args)?;
            let Some(receipt) = book.read_run(run_vid)? else {
                return Err(usage(
                    format!("no import run {:032x} in this book", run_vid.0),
                    "pass the run_vid printed by `fa import run --json`",
                ));
            };
            let verified = if !oids.is_empty() {
                fa_journal::verify_receipt(&receipt, book.context().book_id, &oids)?;
                true
            } else {
                false
            };
            ctx.out.at_book(&book)?;
            let run_hex = format!("{:032x}", receipt.run.0);
            let src_kind = receipt.source.kind_name();
            let root_hex = hex(&receipt.oids_root);
            let hash_hex = hex(&receipt.receipt_hash);
            ctx.out.event(
                "import_receipt",
                vec![
                    ("run_vid", s(&run_hex)),
                    ("source_kind", s(src_kind)),
                    (
                        "document_count",
                        Json::Int(i128::from(receipt.document_count)),
                    ),
                    ("byte_count", Json::Int(i128::from(receipt.byte_count))),
                    ("oids_root", s(&root_hex)),
                    ("receipt_hash", s(&hash_hex)),
                    ("recorded_at", Json::Int(i128::from(receipt.recorded_at.0))),
                    ("verified", Json::Bool(verified)),
                ],
                &format!(
                    "import receipt {run_hex} ({src_kind}, {} docs, {} bytes, receipt {hash_hex}, verified={verified})",
                    receipt.document_count, receipt.byte_count
                ),
            );
            Ok(())
        }
        other => Err(usage(
            format!(
                "`fa import` needs `run` or `receipt`{}",
                other.map_or_else(String::new, |o| format!(" (got `{o}`)"))
            ),
            "fa import run|receipt ...",
        )),
    }
}
